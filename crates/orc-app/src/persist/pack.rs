//! Layer planning: which changed files travel together, and how the finished index
//! points at them.
//!
//! # The two shapes
//!
//! * A file of at least [`OWN_LAYER_MIN_BYTES`] gets a layer to itself. Its bytes are
//!   large enough that content-defined chunking already dedups them well against the
//!   file's own previous version, and keeping it alone means a change to it never
//!   rewrites anything else's layer.
//! * Everything smaller is concatenated, in path order, into **pack** layers cut once a
//!   pack reaches [`PACK_CUT_BYTES`] of plaintext. Packing is what keeps a
//!   hundred-thousand-file tree from becoming a hundred thousand blobs.
//!
//! Path order is the whole trick. The same files in the same order produce the same
//! plaintext, and the sealed codec is convergent, so an unchanged run of a pack yields
//! byte-identical frames and the negotiation skips them — the pack is re-planned every
//! cycle but only its changed neighbourhoods are ever re-sent.
//!
//! # Carrying layers forward
//!
//! The index references *every* file, not just the changed ones. A file the diff carried
//! keeps pointing into the layer of an earlier point, so that layer must appear in the
//! new header — [`assign_refs`] carries it forward by digest. A layer nothing references
//! any more simply does not appear, and registry retention can then drop it.

use std::collections::HashMap;
use std::path::PathBuf;

use crate::persist::tree::{Entry, EntryRef, Kind, LayerRef, Planned};

/// A changed file at least this large is uploaded as its own layer.
pub const OWN_LAYER_MIN_BYTES: u64 = 4 * 1024 * 1024;

/// A pack layer is closed once it holds at least this much plaintext. The last file
/// added may carry it past the cut (by under [`OWN_LAYER_MIN_BYTES`]), which is what
/// bounds a pack's memory at ~68 MiB.
pub const PACK_CUT_BYTES: u64 = 64 * 1024 * 1024;

#[derive(Debug, thiserror::Error)]
pub enum PackError {
    #[error("changed file {0:?} was planned into no layer")]
    Unplanned(String),
    #[error("app data index would carry {0} layers, over the {1} the format allows")]
    TooManyLayers(usize, usize),
}

/// The most layers one point may reference. Far above anything the packing rule
/// produces (a 64 MiB pack cut means ~16 k layers per TiB), it exists so a malformed
/// carry-forward chain cannot grow the header without bound.
pub const MAX_LAYERS: usize = 65_536;

/// Whether a layer holds one big file or a run of small ones.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LayerKind {
    /// One file, uploaded through the two-pass path (never buffered whole).
    Whole,
    /// A run of small files concatenated in path order, held in memory while sealed.
    Pack,
}

/// One file's place in a layer's plaintext.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PlannedFile {
    /// Index-relative path, `/`-separated.
    pub path: String,
    /// Where to read the bytes: inside the frozen capture view.
    pub source: PathBuf,
    /// Byte offset of this file within the layer's plaintext.
    pub offset: u64,
    pub len: u64,
}

/// One layer to build and upload.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LayerPlan {
    pub kind: LayerKind,
    pub files: Vec<PlannedFile>,
    /// Total plaintext the layer will carry.
    pub bytes: u64,
}

/// A layer plan and the layer it turned into once uploaded.
#[derive(Debug, Clone)]
pub struct BuiltLayer {
    pub plan: LayerPlan,
    pub layer: LayerRef,
}

/// Groups the changed files of `planned` into layers, in path order.
///
/// Only regular files that the diff did **not** carry forward are planned; directories,
/// symlinks, and carried files cost nothing to upload.
#[must_use]
pub fn plan_layers(planned: &[Planned]) -> Vec<LayerPlan> {
    let mut layers: Vec<LayerPlan> = Vec::new();
    let mut pack: Vec<PlannedFile> = Vec::new();
    let mut pack_bytes = 0u64;

    for item in planned {
        if item.entry.kind != Kind::File || item.carried.is_some() {
            continue;
        }
        let len = item.entry.size;
        if len >= OWN_LAYER_MIN_BYTES {
            layers.push(LayerPlan {
                kind: LayerKind::Whole,
                files: vec![PlannedFile {
                    path: item.entry.path.clone(),
                    source: item.entry.source.clone(),
                    offset: 0,
                    len,
                }],
                bytes: len,
            });
            // The open pack keeps accumulating: a big file interrupting a run of small
            // ones must not fragment the pack, or the frames either side of it would
            // stop converging with the previous cycle's.
            continue;
        }
        pack.push(PlannedFile {
            path: item.entry.path.clone(),
            source: item.entry.source.clone(),
            offset: pack_bytes,
            len,
        });
        pack_bytes += len;
        if pack_bytes >= PACK_CUT_BYTES {
            layers.push(LayerPlan {
                kind: LayerKind::Pack,
                files: std::mem::take(&mut pack),
                bytes: pack_bytes,
            });
            pack_bytes = 0;
        }
    }
    if !pack.is_empty() {
        layers.push(LayerPlan {
            kind: LayerKind::Pack,
            files: pack,
            bytes: pack_bytes,
        });
    }
    layers
}

/// Total plaintext the planned layers will carry — the "uploaded" figure the node log
/// narrates, before compression and dedup take their cut.
#[must_use]
pub fn planned_bytes(layers: &[LayerPlan]) -> u64 {
    layers.iter().map(|layer| layer.bytes).sum()
}

/// Turns the plan plus the uploaded layers into the index's header layer list and its
/// entries.
///
/// The header lists layers in the order the entries first reference them — carried
/// layers and new ones alike, deduplicated by digest (a freshly sealed layer that
/// happens to converge with a carried one is the same layer, and appears once).
///
/// # Errors
///
/// Returns [`PackError::Unplanned`] if a changed file appears in no built layer (a
/// planning bug, never a runtime condition) and [`PackError::TooManyLayers`] beyond
/// [`MAX_LAYERS`].
pub fn assign_refs(
    planned: &[Planned],
    built: &[BuiltLayer],
) -> Result<(Vec<LayerRef>, Vec<Entry>), PackError> {
    let mut placement: HashMap<&str, (&LayerRef, u64, u64)> = HashMap::new();
    for layer in built {
        for file in &layer.plan.files {
            placement.insert(file.path.as_str(), (&layer.layer, file.offset, file.len));
        }
    }

    let mut layers: Vec<LayerRef> = Vec::new();
    let mut indices: HashMap<String, u32> = HashMap::new();
    let mut entries: Vec<Entry> = Vec::with_capacity(planned.len());

    for item in planned {
        let reference = match item.entry.kind {
            Kind::File => {
                let (layer, offset, len) = if let Some(carried) = &item.carried {
                    (&carried.layer, carried.offset, carried.len)
                } else {
                    placement
                        .get(item.entry.path.as_str())
                        .copied()
                        .ok_or_else(|| PackError::Unplanned(item.entry.path.clone()))?
                };
                let index = if let Some(index) = indices.get(&layer.digest) {
                    *index
                } else {
                    if layers.len() >= MAX_LAYERS {
                        return Err(PackError::TooManyLayers(layers.len() + 1, MAX_LAYERS));
                    }
                    let index = u32::try_from(layers.len()).unwrap_or(u32::MAX);
                    layers.push(layer.clone());
                    indices.insert(layer.digest.clone(), index);
                    index
                };
                Some(EntryRef {
                    l: index,
                    o: offset,
                    n: len,
                })
            }
            Kind::Dir | Kind::Symlink => None,
        };
        entries.push(Entry {
            p: item.entry.path.clone(),
            k: item.entry.kind,
            s: item.entry.size,
            m: item.entry.mtime_ns,
            c: item.entry.ctime_ns,
            mode: item.entry.mode,
            t: item.entry.target.clone(),
            r: reference,
        });
    }
    Ok((layers, entries))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::persist::tree::{Carried, WalkEntry};

    fn planned_file(path: &str, len: u64, carried: Option<Carried>) -> Planned {
        Planned {
            entry: WalkEntry {
                path: path.to_owned(),
                kind: Kind::File,
                size: len,
                mtime_ns: 1,
                ctime_ns: 2,
                mode: 0o644,
                target: None,
                source: PathBuf::from(path),
            },
            carried,
        }
    }

    fn layer(digest: &str) -> LayerRef {
        LayerRef {
            digest: digest.to_owned(),
            size: 1,
        }
    }

    #[test]
    fn small_files_pack_in_path_order_and_cut_at_the_boundary() {
        // Each file is under the own-layer threshold, and 32 of them fill a pack exactly.
        let each = PACK_CUT_BYTES / 32;
        assert!(each < OWN_LAYER_MIN_BYTES, "the files must be pack-sized");
        let planned: Vec<Planned> = (0..70)
            .map(|index| planned_file(&format!("f{index:03}"), each, None))
            .collect();
        let layers = plan_layers(&planned);
        assert_eq!(layers.len(), 3);
        assert_eq!(layers[0].files.len(), 32);
        assert_eq!(layers[0].bytes, PACK_CUT_BYTES);
        assert_eq!(layers[1].files.len(), 32);
        // The tail is emitted short.
        assert_eq!(layers[2].files.len(), 6);
        assert!(layers.iter().all(|layer| layer.kind == LayerKind::Pack));
        // Offsets tile each pack's plaintext exactly.
        for layer in &layers {
            let mut cursor = 0;
            for file in &layer.files {
                assert_eq!(file.offset, cursor);
                cursor += file.len;
            }
            assert_eq!(cursor, layer.bytes);
        }
    }

    #[test]
    fn a_big_file_gets_its_own_layer_without_fragmenting_the_pack() {
        let planned = vec![
            planned_file("a", 100, None),
            planned_file("big", OWN_LAYER_MIN_BYTES, None),
            planned_file("b", 200, None),
        ];
        let layers = plan_layers(&planned);
        assert_eq!(layers.len(), 2);
        assert_eq!(layers[0].kind, LayerKind::Whole);
        assert_eq!(layers[0].files[0].path, "big");
        assert_eq!(layers[1].kind, LayerKind::Pack);
        assert_eq!(
            layers[1]
                .files
                .iter()
                .map(|file| file.path.as_str())
                .collect::<Vec<_>>(),
            ["a", "b"],
            "the small files stay in one run, in path order"
        );
        assert_eq!(layers[1].files[1].offset, 100);
    }

    #[test]
    fn a_file_one_byte_under_the_threshold_still_packs() {
        let layers = plan_layers(&[planned_file("a", OWN_LAYER_MIN_BYTES - 1, None)]);
        assert_eq!(layers[0].kind, LayerKind::Pack);
    }

    #[test]
    fn carried_files_and_non_files_are_never_planned() {
        let mut directory = planned_file("d", 0, None);
        directory.entry.kind = Kind::Dir;
        let planned = vec![
            planned_file(
                "carried",
                OWN_LAYER_MIN_BYTES * 2,
                Some(Carried {
                    layer: layer("sha256:old"),
                    offset: 0,
                    len: OWN_LAYER_MIN_BYTES * 2,
                }),
            ),
            directory,
        ];
        assert!(plan_layers(&planned).is_empty());
    }

    #[test]
    fn refs_carry_previous_layers_forward_in_first_reference_order() {
        let planned = vec![
            planned_file(
                "a",
                10,
                Some(Carried {
                    layer: layer("sha256:old"),
                    offset: 40,
                    len: 10,
                }),
            ),
            planned_file("b", 20, None),
            planned_file(
                "c",
                30,
                Some(Carried {
                    layer: layer("sha256:old"),
                    offset: 50,
                    len: 30,
                }),
            ),
        ];
        let plans = plan_layers(&planned);
        let built = vec![BuiltLayer {
            plan: plans[0].clone(),
            layer: layer("sha256:new"),
        }];
        let (layers, entries) = assign_refs(&planned, &built).expect("refs");
        assert_eq!(
            layers.iter().map(|l| l.digest.as_str()).collect::<Vec<_>>(),
            ["sha256:old", "sha256:new"],
            "the header lists layers in first-reference order"
        );
        assert_eq!(entries[0].r, Some(EntryRef { l: 0, o: 40, n: 10 }));
        assert_eq!(entries[1].r, Some(EntryRef { l: 1, o: 0, n: 20 }));
        assert_eq!(entries[2].r, Some(EntryRef { l: 0, o: 50, n: 30 }));
    }

    #[test]
    fn a_layer_nothing_references_is_dropped_and_a_converged_one_appears_once() {
        let planned = vec![
            planned_file(
                "a",
                10,
                Some(Carried {
                    layer: layer("sha256:same"),
                    offset: 0,
                    len: 10,
                }),
            ),
            planned_file("b", 20, None),
        ];
        // The freshly sealed pack converged with the layer `a` already lives in.
        let built = vec![BuiltLayer {
            plan: plan_layers(&planned)[0].clone(),
            layer: layer("sha256:same"),
        }];
        let (layers, entries) = assign_refs(&planned, &built).expect("refs");
        assert_eq!(layers.len(), 1);
        assert_eq!(entries[1].r.expect("ref").l, 0);
    }

    #[test]
    fn a_changed_file_in_no_built_layer_is_a_planning_error() {
        let planned = vec![planned_file("a", 10, None)];
        let err = assign_refs(&planned, &[]).expect_err("refused");
        assert!(err.to_string().contains("planned into no layer"), "{err}");
    }

    #[test]
    fn directories_and_symlinks_carry_no_reference() {
        let mut directory = planned_file("d", 0, None);
        directory.entry.kind = Kind::Dir;
        let mut link = planned_file("l", 0, None);
        link.entry.kind = Kind::Symlink;
        link.entry.target = Some("d".to_owned());
        let planned = vec![directory, link];
        let (layers, entries) = assign_refs(&planned, &[]).expect("refs");
        assert!(layers.is_empty());
        assert!(entries.iter().all(|entry| entry.r.is_none()));
        assert_eq!(entries[1].t.as_deref(), Some("d"));
    }
}
