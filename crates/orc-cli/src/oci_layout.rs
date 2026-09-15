use std::collections::BTreeMap;
use std::path::Path;

use serde::Serialize;

use crate::build_recipe::BuildArtifact;
use crate::error::{CliError, Result};

pub fn write_layout(path: &Path, artifact: &BuildArtifact, tags: &[String]) -> Result<()> {
    std::fs::create_dir_all(path)
        .map_err(|err| CliError::Operational(format!("create {}: {err}", path.display())))?;
    let layout = serde_json::json!({"imageLayoutVersion": "1.0.0"});
    std::fs::write(
        path.join("oci-layout"),
        serde_json::to_vec_pretty(&layout)
            .map_err(|err| CliError::Operational(format!("encode oci-layout: {err}")))?,
    )
    .map_err(|err| CliError::Operational(format!("write oci-layout: {err}")))?;

    for blob in &artifact.blobs {
        write_blob(path, &blob.digest, &blob.body)?;
    }
    for manifest in &artifact.manifests {
        write_blob(path, &manifest.descriptor.digest, &manifest.body)?;
    }
    let annotations = tags.first().map_or_else(BTreeMap::new, |tag| {
        BTreeMap::from([("org.opencontainers.image.ref.name".to_owned(), tag.clone())])
    });
    let mut manifests = vec![LayoutDescriptor {
        media_type: artifact.root.media_type.clone(),
        digest: artifact.root.digest.clone(),
        size: artifact.root.size,
        artifact_type: None,
        annotations,
    }];
    // Make the layout self-contained: include the recipe referrer's blobs and
    // list its manifest so the embedded artifact.yaml travels with the layout.
    if let Some(recipe) = &artifact.recipe {
        for blob in &recipe.blobs {
            write_blob(path, &blob.digest, &blob.body)?;
        }
        write_blob(
            path,
            &recipe.manifest.descriptor.digest,
            &recipe.manifest.body,
        )?;
        manifests.push(LayoutDescriptor {
            media_type: recipe.manifest.descriptor.media_type.clone(),
            digest: recipe.manifest.descriptor.digest.clone(),
            size: recipe.manifest.descriptor.size,
            artifact_type: Some(crate::app::RECIPE_ARTIFACT_TYPE.to_owned()),
            annotations: BTreeMap::new(),
        });
    }
    let index = LayoutIndex {
        schema_version: 2,
        manifests,
    };
    let body = serde_json::to_vec_pretty(&index)
        .map_err(|err| CliError::Operational(format!("encode index.json: {err}")))?;
    std::fs::write(path.join("index.json"), body)
        .map_err(|err| CliError::Operational(format!("write index.json: {err}")))?;
    Ok(())
}

fn write_blob(root: &Path, digest: &str, body: &[u8]) -> Result<()> {
    let Some(hex) = digest.strip_prefix("sha256:") else {
        return Err(CliError::Operational(format!(
            "unsupported digest {digest:?}"
        )));
    };
    let path = root.join("blobs/sha256").join(hex);
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .map_err(|err| CliError::Operational(format!("create {}: {err}", parent.display())))?;
    }
    std::fs::write(&path, body)
        .map_err(|err| CliError::Operational(format!("write {}: {err}", path.display())))
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct LayoutIndex {
    schema_version: u8,
    manifests: Vec<LayoutDescriptor>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct LayoutDescriptor {
    media_type: String,
    digest: String,
    size: u64,
    #[serde(rename = "artifactType", skip_serializing_if = "Option::is_none")]
    artifact_type: Option<String>,
    #[serde(skip_serializing_if = "BTreeMap::is_empty")]
    annotations: BTreeMap<String, String>,
}
