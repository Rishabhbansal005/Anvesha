import logging
from app.database.supabase_client import supabase
from app.services.campaign_service import campaign_service

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("CampaignBackfill")

def backfill_campaigns():
    cases = supabase.query("cases")
    logger.info(f"Loaded {len(cases)} cases.")
    
    # Sort cases by id ascending
    cases = sorted(cases, key=lambda c: c.get("id") or 0)
    
    correlated_count = 0
    for case in cases:
        case_id = case.get("id") or case.get("case_number")
        
        # Check if already assigned
        fresh_cases = supabase.query("cases", filters={"id": f"eq.{case.get('id')}"})
        curr_case = fresh_cases[0] if fresh_cases else case
        if curr_case.get("campaign_id"):
            logger.info(f"Case {curr_case.get('case_number')} already in campaign {curr_case.get('campaign_id')}. Skipping.")
            continue
        
        # Fetch associated emails
        emails = supabase.query("emails", filters={"case_id": f"eq.{case_id}"})
        email_data = emails[0] if emails else {}
        
        # Fetch associated IOCs
        iocs = supabase.query("iocs", filters={"case_id": f"eq.{case_id}"})
        
        # Fetch associated infra
        infras = supabase.query("infrastructure_intelligence", filters={"case_id": f"eq.{case_id}"})
        infra_data = infras[0] if infras else {}
        
        logger.info(f"Evaluating case {curr_case.get('case_number')} (ID: {curr_case.get('id')})...")
        res = campaign_service.correlate_and_assign_case(
            case_data=curr_case,
            email_data=email_data,
            observables=iocs,
            infra_data=infra_data,
            lookalike_evidence={}
        )
        if res:
            correlated_count += 1
            logger.info(f"-> Assigned to campaign: {res['campaign']['campaign_id']} (matched with {res.get('matched_case_number')})")

    logger.info(f"Backfill complete! Total correlations formed: {correlated_count}")
    
    # Check resulting campaigns
    camps = supabase.query("campaigns")
    logger.info(f"Total campaigns in DB: {len(camps)}")
    for camp in camps:
        logger.info(f"Campaign ID: {camp.get('id')} | Code: {camp.get('campaign_id')} | Name: {camp.get('name')} | Cases: {camp.get('case_count')}")

if __name__ == "__main__":
    backfill_campaigns()
