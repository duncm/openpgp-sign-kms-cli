#!/usr/bin/env python3
"""Confirm a unique signing description reaches CloudTrail (AWS CLI credentials)."""
import base64,datetime,json,subprocess,sys,time
marker='description/'+base64.urlsafe_b64encode(sys.argv[1].encode()).decode().rstrip('=')
start=(datetime.datetime.now(datetime.timezone.utc)-datetime.timedelta(hours=1)).isoformat()
for attempt in range(30):
 result=subprocess.run(['aws','cloudtrail','lookup-events','--lookup-attributes','AttributeKey=EventName,AttributeValue=Sign','--start-time',start,'--output','json'],check=True,capture_output=True,text=True)
 for event in json.loads(result.stdout).get('Events',[]):
  record=json.loads(event['CloudTrailEvent'])
  if marker in record.get('userAgent',''):
   print('CloudTrail description confirmed; requestID='+record.get('requestID','unknown'));sys.exit(0)
 if attempt<29:time.sleep(20)
raise SystemExit('CloudTrail description not found within 10 minutes')
