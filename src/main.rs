mod fieldservice_audit;
use fieldservice_audit::{blast_radius, DispatchStatus, Infrai, TechnicianFollowUp, WorkOrderPhoto};
use serde_json::json;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let api = Infrai::from_env()?;
    let leaked = api.create_key("fieldservice-incident-temporary").await?;
    let key_id = leaked.get("id").and_then(|v| v.as_str()).ok_or("create response missing id")?;
    api.report_compromise(key_id).await?;
    let rotated = api.rotate_key(key_id).await?;
    let event = json!({"event":"fieldservice.key_rotation","key_id":key_id,"replacement":rotated});
    api.ingest_log(&event).await?;
    let touched = api.search_logs(&format!("key_id:{key_id}")).await?;
    let statuses = vec![DispatchStatus { work_order_id: "WO-1042".into(), status: "dispatched".into(), technician: "tech-18".into() }];
    let photos = vec![WorkOrderPhoto { work_order_id: "WO-1042".into(), photo_id: "photo-9".into(), sha256: "sha256:demo".into() }];
    let followups = vec![TechnicianFollowUp { work_order_id: "WO-1042".into(), note: "customer callback scheduled".into() }];
    println!("rotation recorded; {} work order(s) in the local business sample; blast-radius logs: {touched}", blast_radius(&statuses, &photos, &followups));
    Ok(())
}

