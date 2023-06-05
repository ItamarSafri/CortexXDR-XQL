# CortexXDR-XQL
Cortex XDR XQL Queries

NEW LOCAL USER CREATION
dataset = xdr_data 
    | filter event_type = EVENT_LOG and action_evtlog_event_id = 4720
    | fields action_evtlog_data_fields as aedf, agent_hostname
    | filter aedf != null
    | alter UserName = replace(json_extract(aedf, "$.TargetUserName"), "\"","")
    | alter DomainName = replace(json_extract(aedf, "$.TargetDomainName"), "\"","")
    | alter WhoDid = replace(json_extract(aedf, "$.SubjectUserName"), "\"","")
    | filter (UserName not contains """lenovo_tmp_""")
