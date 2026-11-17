"""Normalize selected Windows Security events exported as JSON Lines (not binary EVTX)."""
def normalize_windows(value):
    system = value.get('System', {})
    winlog = value.get('winlog', {})
    if not isinstance(system, dict) or not isinstance(winlog, dict):
        return None
    event_id = system.get('EventID') or winlog.get('event_id') or value.get('EventID')
    if isinstance(event_id, dict):
        event_id = event_id.get('#text')
    if str(event_id) not in {'4624','4625','4688'}:
        return None
    event_id = int(event_id)
    data = value.get('EventData', winlog.get('event_data', {}))
    if not isinstance(data, dict):
        raise ValueError('Windows EventData must be an object with named fields')
    timestamp = value.get('@timestamp') or system.get('TimeCreated') or value.get('TimeCreated')
    if isinstance(timestamp, dict):
        timestamp = timestamp.get('SystemTime') or timestamp.get('@SystemTime')
    host = system.get('Computer') or winlog.get('computer_name') or value.get('MachineName')
    if not isinstance(timestamp,str) or not isinstance(host,str) or not host:
        raise ValueError('Windows event requires an ISO timestamp and computer name')
    prefix = 'Subject' if event_id == 4688 else 'Target'
    user = data.get(prefix+'UserName') or 'unknown'
    domain = data.get(prefix+'DomainName')
    if isinstance(domain,str) and domain not in {'','-'} and user != 'unknown':
        user = domain + chr(92) + str(user)
    ip = data.get('IpAddress') or 'UNKNOWN'
    if ip in {'-',''}:
        ip = 'UNKNOWN'
    action = 'process' if event_id == 4688 else 'login'
    logon_type = str(data.get('LogonType',''))
    if event_id != 4688 and logon_type in {'4','5','9'}:
        action = 'service_logon'
    result = dict(timestamp=timestamp,user=str(user),ip=str(ip),host=host,country='UNKNOWN',
                  action=action,status='failed' if event_id == 4625 else 'success',
                  event_type='windows_security',windows_event_id=event_id,logon_type=logon_type)
    if event_id == 4688:
        result['command'] = str(data.get('CommandLine') or data.get('ProcessCommandLine') or '')
        result['process'] = str(data.get('NewProcessName') or '')
        result['pid'] = str(data.get('NewProcessId') or '')
    return result
