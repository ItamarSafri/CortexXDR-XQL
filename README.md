# CortexXDR-XQL
Cortex XDR XQL Queries

#### NEW LOCAL USER CREATION

    dataset = xdr_data 
    | filter event_type = EVENT_LOG and action_evtlog_event_id = 4720
    | fields action_evtlog_data_fields as aedf, agent_hostname
    | filter aedf != null
    | alter UserName = replace(json_extract(aedf, "$.TargetUserName"), "\"","")
    | alter DomainName = replace(json_extract(aedf, "$.TargetDomainName"), "\"","")
    | alter WhoDid = replace(json_extract(aedf, "$.SubjectUserName"), "\"","")
    
    
#### LOCAL USER ENALBED

    dataset = xdr_data 
    | filter event_type = EVENT_LOG and action_evtlog_event_id = 4722
    | fields action_evtlog_data_fields as aedf, agent_hostname
    | filter aedf != null
    | alter UserName = json_extract(aedf, "$.TargetUserName")
    | alter DomainName = json_extract(aedf, "$.TargetDomainName")
    | alter WhoDid = json_extract(aedf, "$.SubjectUserName")
   
#### LOGINS BY EVENT ID 4624

    dataset = xdr_data 
    | filter event_type = EVENT_LOG and action_evtlog_event_id = 4624
    | fields action_evtlog_data_fields as aedf, agent_hostname
    | filter aedf != null
    | alter UserName = replace(json_extract(aedf, "$.TargetUserName"), "\"","")
    | alter DomainName = replace(json_extract(aedf, "$.TargetDomainName"), "\"","")
    | comp count(UserName) as Counter by UserName, agent_hostname, DomainName
   
#### USER ADDED TO ADMINISTRATORS GROUP
    dataset = xdr_data
    | filter event_type = EVENT_LOG and action_evtlog_event_id = 4732
    | alter WhoDid = action_evtlog_data_fields->SubjectUserName
    | alter domainname = action_evtlog_data_fields->SubjectDomainName
    | alter GroupSID = action_evtlog_data_fields->TargetSid
    | alter MemberSID = action_evtlog_data_fields->MemberSid
    | alter GroupName = action_evtlog_data_fields->TargetUserName
    | filter (GroupSID = "S-1-5-32-544")
    | filter (MemberSid not contains "-512")
    | filter WhoDid not contains "$"
    | join type = left (dataset=ad_users) as ad ad.security_identifier = MemberSID 
    | dedup agent_hostname, action_evtlog_data_fields, domainname, WhoDid, sam_account_name, GroupName, GroupSID
    
    
   	
#### DOMAIN ADMIN LOGON WITH EXCLUTION BY AD GROUP & DCs
    config case_sensitive = false
    | dataset = xdr_data 
    | filter event_type = EVENT_LOG and action_evtlog_event_id = 4624 
    | fields action_evtlog_data_fields as aedf, agent_hostname 
    | filter aedf != null
    | alter UserName = aedf->TargetUserName
    | alter DomainName = aedf->TargetDomainName
    | alter LogonType = aedf->LogonType
    | alter SourceIP = aedf->IpAddress
    | alter UserSID = aedf->TargetUserSid
    | join type=left (preset=ad_users | fields security_identifier , member_of ) as ad ad.security_identifier = UserSID
    | join type=left conflict_strategy=both (preset = ad_computers | fields name, OU, security_group_list) as adcoms adcoms.name = agent_hostname
    | alter isDomainAdmin = arrayfilter(member_of , "@element" = "CN=Domain Admins,CN=Users,DC=Domain,DC=com")
    | alter isExcluded = arrayfilter(security_group_list , "@element" = "CN=Exclude-Group,OU=Test,DC=Domain,DC=com")
    | filter OU != "Domain Controllers"
    | filter isDomainAdmin != null
    | filter isExcluded != "CN=Exclude-Group,OU=Test,DC=Domain,DC=com"
    | fields UserName, agent_hostname, DomainName, logonType, SourceIP, isDomainAdmin, isExcluded, member_of, security_group_list
    | dedup UserName, agent_hostname, DomainName, logonType, SourceIP
