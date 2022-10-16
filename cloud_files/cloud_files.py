# -*- coding: utf-8 -*-
'''
Created on 26.06.2020
Production version:  1  (25.02.2021)

@author: Ivan Diakonenko
'''
import datetime
import time
import hashlib
import base64
import os
import re
import io
import string
import rsa
import MySQLdb
from md5 import md5
from StringIO import StringIO
from Crypto.Cipher import AES
from Crypto import Random

from django.http import HttpResponse, HttpResponseRedirect, Http404,HttpResponseNotFound,HttpResponsePermanentRedirect
import json
from django.db.models.query import Q 

from models import Clients, Lic_online, Cert_online, CF_clients_keys, CF_files, CF_lock_files, CF_rsakeys, CF_sessions, CF_log_access   
from settings import *
from log_util import *
from django.utils.crypto import get_random_string
from django.db.models import Sum

from django.views.decorators.http import require_http_methods
from django.views.decorators.csrf import csrf_exempt
from django.conf import settings

VALID_KEY_CHARS = string.ascii_lowercase + string.digits

SECRET_APP_ORDER_KEY = 'xxxxxxxxxxxxxx'
DEFAULT_ANSWER_ERROR = 'ivalid data'
INV_FORMAT_ANSWER_ERROR = 'invalid format'
LOCK_ANSWER_ERROR = 'lock file'
DATEFORMAT_ANSWER_ERROR = 'date format error'
LOCK_TIME_SEC = 3   # time to block file in the cloud while is updated, seconds
STORAGE_AES_KEY = '\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'

# time to store removed file on server after deletion
RESERVED_STORE_DAYS = 1
COMMON_STORE_DAYS = 7

# historical time periods (days) to keep reserved file in cloud and how many files we should keep in each interval
BACKUP_STORE_INTERVALS = [{'days': 365, 'cnt': 2},{'days': 180, 'cnt': 4},{'days': 31, 'cnt': 5},{'days': 7, 'cnt': 5},{'days': 4, 'cnt': 10},{'days': 1, 'cnt': 12}]
    
# regular templates
FILE_ID_RE = re.compile(r"^\w{12}$")
SESSION_KEY_RE = re.compile(r"^\w{32}$")
FILE_ADD_NUM_RE = re.compile(r"\((\d+)\)$")

def AsJSON(json_answ):
    def encode_date(obj):
        if isinstance(obj, datetime.datetime):
            return '%.4d-%.2d-%.2d %.2d:%.2d:%.2d' %(obj.year, obj.month, obj.day, obj.hour, obj.minute, obj.second)
        elif isinstance(obj, datetime.date):
            return '%.2d.%.2d.%.4d' %(obj.day, obj.month, obj.year)
        elif isinstance(obj, str):
            return unicode(obj)
        elif obj==None:
            return ""
        else:    
            raise TypeError(repr(obj) + " is not JSON serializable")

    return json.dumps(json_answ, default=encode_date) # , ensure_ascii=False for test only  

def JSONResponse(json_answ):
    return HttpResponse(AsJSON(json_answ), "application/json; charset=utf-8")


def RSAKeysToHex(i):
    s = ('%x' % i).upper()
    while len(s) % 2:
        s = '0' + s
    i = len(s)-2
    r = ''
    while i>=0:
        r = r + s[i:i+2]
        i = i - 2
    return r

def GenDefaultKeyPairForClient(context, client):
    (pubkey, privkey) = rsa.newkeys(512)
    # make sure pubkey.e=65537 !!!
    while pubkey.e!=65537:
        (pubkey, privkey) = rsa.newkeys(512) 
    key = CF_rsakeys(privkey_hex = RSAKeysToHex(privkey.d) + 'X' + RSAKeysToHex(privkey.n), pubkey_hex=RSAKeysToHex(pubkey.n))
    key.save()
    DebugLog(context, 'Created rsa keyId=%d' % key.id)
    keys = CF_clients_keys(client=client, key = key, default=1)
    keys.save()
    sessions = CF_sessions.objects.filter(Q(client_id=client.client_id))
    for s in sessions:
        s.client_key_md5 = ''
        s.save()
    
def AddCommonKeyPairToClient(context, client, key_id):
    keys = CF_clients_keys.objects.filter(Q(client=client) & Q(key=CF_rsakeys.objects.get(pk=key_id)))
    if keys:
        return
    keys = CF_clients_keys(client=client, key = CF_rsakeys.objects.get(pk=key_id), default=0)
    keys.save()
    DebugLog(context, 'Add reference to common keyId=%d' % key_id)
    sessions = CF_sessions.objects.filter(Q(client_id=client.client_id))
    for s in sessions:
        s.client_key_md5 = ''
        s.save()
    
# key_type: 'private'/'public'    
def EncodeKey(context, key, key_type):
    if key_type=='private':
        iType = 0
        key_hex = CF_rsakeys.objects.get(pk=key.key_id).privkey_hex
    elif key_type=='public':
        iType = 1
        key_hex = CF_rsakeys.objects.get(pk=key.key_id).pubkey_hex
    else:
        ErrorLog(context, 'Undefined key type: ' + key_type)
        raise HtttpReqError(INV_FORMAT_ANSWER_ERROR, HTTP_REQUEST_ERR)
    s = '%.6d%d%d%s' % (key.key_id, key.default, iType, key_hex)
    while len(s) % 32!=0:
        s += '\x00'
    
    try:
        cipher = AES.new(STORAGE_AES_KEY, AES.MODE_ECB)
    except Exception, e:
        ErrorLog(context, 'Error encoding cf keys: ' + e.message)
    return base64.b64encode(cipher.encrypt(s))
    
    
def SendPrivateKeysToClient(context, keys):
    res = []
    for k in keys:
        try:
            res += [{'id': k.key_id, 'raw': EncodeKey(context, k, 'private')}]
        except:
            None
    return res

def GetPrivateKeysMD5(context, keys):
    s = ''
    for k in keys:
        try:
            if k.default==1:
                s = s + '[%d]%s' % (k.key_id, CF_rsakeys.objects.get(pk=k.key_id).privkey_hex)
            else:     
                s = s + '<%d>%s' % (k.key_id, CF_rsakeys.objects.get(pk=k.key_id).privkey_hex)
        except:
            None
    return md5(s).hexdigest()
    

def get_token(context, req):
    if not 'cid' in req or not 'uid' in req:
        raise HtttpReqError(INV_FORMAT_ANSWER_ERROR, HTTP_REQUEST_ERR)
    uid = req['uid']
    cid = req['cid']
        
    if len(uid)<>20 or len(cid)<>9:
        DebugLog(context, 'Check attr length failure')
        raise HtttpReqError(DEFAULT_ANSWER_ERROR, HTTP_REQUEST_ERR)
      
    today = datetime.date.today()
    
    def check_hash(dt):
        dig = hashlib.sha1(cid + str(dt.day) + uid[0:4] + SECRET_APP_ORDER_KEY)
        return dig.hexdigest()[0:16].lower()==uid[4:].lower()    
    
    if check_hash(today) or check_hash(today - datetime.timedelta(days=1)) or check_hash(today + datetime.timedelta(days=1)):
        DebugLog(context, 'uid hash checked')
        DebugLog(context, 'try to find cert sys_id=%s, prg_id=%s, cert_id=%s' % (cid[0:3], cid[3:6], cid[6:]))
        cert = Cert_online.objects.filter(Q(sys_id__endswith=cid[0:3]) & Q(prg_id__endswith=cid[3:6]) & Q(cert_id__endswith=cid[6:]))
        if len(cert)==1:
            cert = cert[0]
            DebugLog(context, 'Online cert found certId=' + cert.cert_id)
            license = Lic_online.objects.filter(Q(client_id=cert.client_id) & Q(lic_num=cert.lic_num))
        elif len(cert)==0:
            DebugLog(context, 'Error no onlne cert found')
            raise HtttpReqError(DEFAULT_ANSWER_ERROR, HTTP_REQUEST_ERR)
        else:
            DebugLog(context, 'Error too many onlne cert found')
            raise HtttpReqError(DEFAULT_ANSWER_ERROR, HTTP_REQUEST_ERR)
    else:
        DebugLog(context, 'Check uid hash failure')
        raise HtttpReqError(DEFAULT_ANSWER_ERROR, HTTP_REQUEST_ERR)
    
            
    client = Clients.objects.filter(client_id=cert.client_id)
    if not client:
        DebugLog(context, 'Error client not found')
        raise HtttpReqError(DEFAULT_ANSWER_ERROR, HTTP_REQUEST_ERR)
    
    client = client[0]
        
    log = CF_log_access(client_id = client.client_id, action = 'get_token')
    log.save()
        
    if not license:
        DebugLog(context, 'Error license not found')
        raise HtttpReqError(DEFAULT_ANSWER_ERROR, HTTP_REQUEST_ERR)
    
    keys = CF_clients_keys.objects.filter(Q(client=client) & Q(default=1))
    if not keys:
        DebugLog(context, 'No keys found for client_id=%d. Start to generate' % cert.client_id)
        GenDefaultKeyPairForClient(context, client)
    
   # TODO common directory can be different for countries 
   # AddCommonKeyPairToClient(context, client, 1)
       
    # get list of keys for the client   
    keys = CF_clients_keys.objects.filter(Q(client=client)).order_by('key_id')
    
    DebugLog(context, 'Found %d keys for client_id=%d' % (len(keys), cert.client_id))
    
    json_answ = {"answ_code": 0, "token_id": ""}
    
    client_key_md5 = ''
    server_key_md5 = GetPrivateKeysMD5(context, keys)
    DebugLog(context, 'MD5 hash=%s' % server_key_md5)
        
    if 'key_sign' in req:
        client_key_md5 = req['key_sign']

    sessions = CF_sessions.objects.filter(Q(client_id=client.client_id))
    for s in sessions:
        if s.session_key[0:3]==cid[6:].lower() and s.end_date<=datetime.datetime.now():
            # delete old sessions for client
            s.delete()
        elif s.session_key[0:3]==cid[6:].lower():
            DebugLog(context, 'Open session found. Token_id provided to answer')
            json_answ['token_id'] = s.session_key
        elif s.end_date<=datetime.datetime.now():
            s.delete()
            
    if not json_answ['token_id']:
        s = CF_sessions(session_key=cid[6:].lower() + get_random_string(29, VALID_KEY_CHARS), end_date=datetime.datetime.now() + datetime.timedelta(days=3), client_id=client.client_id)
        s.save()
        json_answ['token_id'] = s.session_key
        DebugLog(context, 'New session created. Tokem_id provided to answer')
     
    if client_key_md5=='' or (server_key_md5!=client_key_md5):
         DebugLog(context, 'Found difference between server key sign and client key sign')
         json_answ['keys'] = SendPrivateKeysToClient(context, keys)
    
    DebugLog(context, 'Request processed successfully')    
    return json_answ

def file_list(context, req):
    if not 'token_id' in req:
        DebugLog(context, 'Mandatory tag token_id not found')
        raise HtttpReqError(INV_FORMAT_ANSWER_ERROR, HTTP_REQUEST_ERR)
    
    token_id = req['token_id'].lower()
    if not SESSION_KEY_RE.search(token_id):
        DebugLog(context, 'Invalid token_id format')
        raise HtttpReqError(INV_FORMAT_ANSWER_ERROR, HTTP_REQUEST_ERR)
    
    session = CF_sessions.objects.filter(Q(session_key=token_id) & Q(end_date__gte=datetime.datetime.now()))
    if not session:
        raise HtttpReqError(DEFAULT_ANSWER_ERROR, HTTP_REQUEST_ERR)

    session = session[0]
    
    #log = CF_log_access(client_id = session.client_id, action = 'file_list')
    #log.save()
    
    json_answ = {"answ_code": 0, "file_list": []}
    backup_filelist = []
        
    fl = CF_files.objects.filter(Q(owner_id=session.client_id) & Q(delete_date__isnull=True))
    for f in fl:
        rec = {"id": f.file_id, "ts": f.file_timestamp, "t": f.file_type, "d": f.file_date}
        if f.file_type!="R":
            rec["name"] = f.file_name
            json_answ["file_list"].append(rec)
        elif f.parent_file_id:
            rec["parent_id"] = f.parent_file_id
            backup_filelist.append(rec)
    
    for rec in backup_filelist: 
        json_answ["file_list"].append(rec)
    
    return json_answ

def show_trash(context, req):
    if not 'token_id' in req:
        DebugLog(context, 'Mandatory tag token_id not found')
        raise HtttpReqError(INV_FORMAT_ANSWER_ERROR, HTTP_REQUEST_ERR)
    
    token_id = req['token_id'].lower()
    if not SESSION_KEY_RE.search(token_id):
        DebugLog(context, 'Invalid token_id format')
        raise HtttpReqError(INV_FORMAT_ANSWER_ERROR, HTTP_REQUEST_ERR)
    
    session = CF_sessions.objects.filter(Q(session_key=token_id) & Q(end_date__gte=datetime.datetime.now()))
    if not session:
        raise HtttpReqError(DEFAULT_ANSWER_ERROR, HTTP_REQUEST_ERR)

    session = session[0]
    
    log = CF_log_access(client_id = session.client_id, action = 'show_trash')
    log.save()
    
    json_answ = {"answ_code": 0, "file_list": []}
    backup_filelist = []
        
    fl = CF_files.objects.filter(Q(owner_id=session.client_id) & Q(delete_date__isnull=False))
    for f in fl:
        rec = {"id": f.file_id, "ts": f.file_timestamp, "t": f.file_type, "d": f.file_date}
        if f.file_type!="R":
            rec["name"] = f.file_name
            json_answ["file_list"].append(rec)
    
    for rec in backup_filelist: 
        json_answ["file_list"].append(rec)
    
    return json_answ
    
def upload_req(context, req):
    if not 'token_id' in req or not 't' in req or not 'name' in req or not 'd' in req:
        DebugLog(context, 'Mandatory tags not found')
        raise HtttpReqError(INV_FORMAT_ANSWER_ERROR, HTTP_REQUEST_ERR)
    
    token_id = req['token_id'].lower()
    if not SESSION_KEY_RE.search(token_id):
        DebugLog(context, 'Invalid token_id format')
        raise HtttpReqError(INV_FORMAT_ANSWER_ERROR, HTTP_REQUEST_ERR)
    
    if not req['t'] in ('P', 'R', 'C', 'E'):
        raise HtttpReqError(INV_FORMAT_ANSWER_ERROR, HTTP_REQUEST_ERR)
    
    if req['t']=='R':
        if not 'parent_id' in req:
            raise HtttpReqError(INV_FORMAT_ANSWER_ERROR, HTTP_REQUEST_ERR)
        if not CF_files.objects.filter(Q(file_id=req['parent_id']) & Q(file_type='P')).exists():
            raise HtttpReqError(DEFAULT_ANSWER_ERROR, HTTP_REQUEST_ERR)
    
    try:
        file_date = datetime.datetime.strptime(req['d'], '%Y-%m-%d %H:%M:%S')
    except:
        raise HtttpReqError(DATEFORMAT_ANSWER_ERROR, HTTP_REQUEST_ERR)
    
    file_name = req['name'][:254]
    if not file_name:
        DebugLog(context, 'Error provided empty file name')
        raise HtttpReqError(INV_FORMAT_ANSWER_ERROR, HTTP_REQUEST_ERR)
    
    session = CF_sessions.objects.filter(Q(session_key=token_id) & Q(end_date__gte=datetime.datetime.now()))
    if not session:
        raise HtttpReqError(DEFAULT_ANSWER_ERROR, HTTP_REQUEST_ERR)
    
    session = session[0]
    if 'id' in req:
        if not 'ts' in req:
            DebugLog(context, 'Mandatory tag ts not found if file_id provided')
            raise HtttpReqError(INV_FORMAT_ANSWER_ERROR, HTTP_REQUEST_ERR)
        timestamp = int(req['ts'])
        
        file_id = req['id'].lower()
        if not FILE_ID_RE.search(file_id):
            DebugLog(context, 'Invalid file_id format')
            raise HtttpReqError(INV_FORMAT_ANSWER_ERROR, HTTP_REQUEST_ERR)
        
        DebugLog(context, 'User provide file_id=%s try to find file' % file_id)
        file_rec = CF_files.objects.filter(Q(file_id=file_id) & Q(delete_date__isnull=True))
        if file_rec:
            file_rec = file_rec[0]
            if file_rec.file_type!='P':
                DebugLog(context, 'Error it is possible to rewrite private file only')
                raise HtttpReqError(DEFAULT_ANSWER_ERROR, HTTP_REQUEST_ERR)
            
            if timestamp==0:
                DebugLog(context, 'File should be replaced timestamp not checked (provided 0)')
            elif int(file_rec.file_timestamp)>timestamp:
                DebugLog(context, 'Provided timestamp expired. New version of file is detected')
                file_id = None
                match = FILE_ADD_NUM_RE.search(file_name)
                file_num = None
                if match:
                    try:
                        file_num = int(match.group(1))
                        i = 1
                        while i<20:
                            file_num += 1
                            i += 1 
                            fn2 = FILE_ADD_NUM_RE.sub('(%d)' % file_num, file_name)
                            if not CF_files.objects.filter(Q(owner_id=session.client_id) & Q(file_name=fn2) & Q(delete_date__isnull=True)):
                                file_name = fn2
                                DebugLog(context, 'Generated new unique file name: %s' % file_name)
                                break
                        if i==20:
                            file_num = None
                    except:
                        None
                
                if not file_num:
                    file_name = file_name + ' (1)'
                    DebugLog(context, 'Generated new unique file name: %s' % file_name)  
            
        else:
            DebugLog(context, 'File_id not found. Generate new')
            file_id = None
        
    else:
        DebugLog(context, 'User doesnt provide file_id. Generate new')
        file_id = None
    
    if not file_id:
        while True:
            file_id = get_random_string(12, VALID_KEY_CHARS)
            if not CF_files.objects.filter(file_id=file_id).exists():
                break    
        DebugLog(context, 'Generated file_id=%s' % file_id)

    log = CF_log_access(client_id = session.client_id, action = 'upload_req', file_id = file_id)
    log.save()
    
    lock = CF_lock_files.objects.filter(Q(file_id=file_id))
    if lock:
        lock = lock[0]
        DebugLog(context, 'Existed lock for file found')    
        if lock.session_key!=session.session_key and lock.end_date>datetime.datetime.now():
            DebugLog(context, 'Error it is an active lock')
            raise HtttpReqError(LOCK_ANSWER_ERROR, HTTP_REQUEST_ERR)
        lock.owner_id = session.client_id
        lock.end_date = datetime.datetime.now() + datetime.timedelta(seconds=LOCK_TIME_SEC) 
    else:
        lock = CF_lock_files(file_id = file_id, owner_id = session.client_id, end_date=datetime.datetime.now() + datetime.timedelta(seconds=LOCK_TIME_SEC))
    lock.session_key = session.session_key
    lock.file_timestamp = datetime.datetime.now().strftime('%Y%m%d%H%M%S')
    lock.file_type = req['t']
    lock.file_date = file_date
    if req['t']=='R':
        lock.parent_file_id = req['parent_id']
    else:
        lock.file_name = file_name
        
    json_answ = {"answ_code": 0, "id": file_id, "ts":  lock.file_timestamp, "name": file_name}
    lock.save()
    CF_lock_files.objects.filter(Q(owner_id=session.client_id) & Q(end_date__lte=datetime.datetime.now())).delete()
    return json_answ

def upload_file(context, req, file_data):
    if not 'token_id' in req or not 'id' in req or not "ts" in req:
        DebugLog(context, 'Mandatory tags not found')
        raise HtttpReqError(INV_FORMAT_ANSWER_ERROR, HTTP_REQUEST_ERR)
    
    token_id = req['token_id'].lower()
    if not SESSION_KEY_RE.search(token_id):
        DebugLog(context, 'Invalid token_id format')
        raise HtttpReqError(INV_FORMAT_ANSWER_ERROR, HTTP_REQUEST_ERR)
    
    file_id = req['id'].lower()
    if not FILE_ID_RE.search(file_id):
        DebugLog(context, 'Invalid file_id format')
        raise HtttpReqError(INV_FORMAT_ANSWER_ERROR, HTTP_REQUEST_ERR)
        
    lock = CF_lock_files.objects.filter(Q(session_key=token_id) & Q(file_id=file_id) & Q(end_date__gte=datetime.datetime.now()))
    if not lock:
        DebugLog(context, 'Error session key and file_id not found in lock table')
        raise HtttpReqError(DEFAULT_ANSWER_ERROR, HTTP_REQUEST_ERR)
    lock = lock[0]
    if lock.file_timestamp != req['ts']:
        DebugLog(context, 'Invalid file timestamp')
        raise HtttpReqError(DEFAULT_ANSWER_ERROR, HTTP_REQUEST_ERR)
    DebugLog(context, 'lock found')
    dest_file = os.path.join(CLOUD_FILE_DIR, file_id + '_' + req['ts'])
    start_time = time.time()
    
    if os.path.exists(dest_file):
        os.remove(dest_file)

    DebugLog(context, 'start load file')       
    buf = io.BytesIO()
    if file_data.multiple_chunks:
        for c in file_data.chunks():
            buf.write(c)
            curr_time = time.time()
            if curr_time - start_time > 2.0:
                lock.end_date = datetime.datetime.now() + datetime.timedelta(seconds=5)
                lock.save()
                start_time = curr_time
    else:
        buf.write(file_data.read())
    file_size = buf.tell()
    buf.seek(0, os.SEEK_SET)
    
    f = open(dest_file, 'wb')
    f.write(buf.getvalue())
    f.close()
        
    buf.close()
    DebugLog(context, 'File with size %d uploaded. Lock deleted' % file_size)
    
    if file_size>9000000:
        lock.delete()
        DebugLog(context, 'Exceed maximum file size. Raise error')
        os.remove(dest_file)
        raise HtttpReqError(DEFAULT_ANSWER_ERROR, HTTP_REQUEST_ERR)

    file_rec = CF_files.objects.filter(Q(file_id=file_id))
    if not file_rec:
        file_rec = CF_files(file_id = file_id)
        DebugLog(context, 'Create new CF_files record')
    else:
        file_rec = file_rec[0] 
        DebugLog(context, 'CF_files record found')
        
    log = CF_log_access(client_id = lock.owner_id, action = 'upload_file', file_id = file_rec.file_id)
    log.save()
            
    file_rec.file_timestamp = lock.file_timestamp
    file_rec.file_type = lock.file_type
    file_rec.parent_file_id = lock.parent_file_id
    file_rec.file_name = lock.file_name
    file_rec.file_date = lock.file_date
    file_rec.owner_id = lock.owner_id
    file_rec.file_size = file_size
    file_rec.update_date = datetime.datetime.now()
    file_rec.save() 
    lock.delete()    
    DebugLog(context, 'lock record deleted')
    
    final_file = os.path.join(CLOUD_FILE_DIR, file_id)
    if os.path.exists(final_file):
        os.remove(final_file)
    os.rename(dest_file, final_file)
    DebugLog(context, 'Temporary file renamed to %s' % file_id)
    json_answ = {"answ_code": 0}
    
    if file_rec.file_type == 'R':
        DebugLog(context, 'check and delete old backup files')
        backup_files = CF_files.objects.filter(Q(owner_id=file_rec.owner_id) & Q(parent_file_id=file_rec.parent_file_id) & Q(file_type='R') & Q(delete_date__isnull=True)).order_by('file_timestamp')
                 
        if len(backup_files)>5:
            i = 0
            t = datetime.date.today() 
            today_ts = int('%4.d%.2d%.2d' % (t.year,t.month,t.day))

            # initialize delete counter for each copy (interval of time could increase this counter by 1)
            for f in backup_files:
                f.del_cnt = 0
            
            while i<len(BACKUP_STORE_INTERVALS):
                # Calculate how many reserved copies stored between adjacent intervals
                total_cnt = 0
                for f in reversed(backup_files):
                    if int(f.file_timestamp[:8])>today_ts-BACKUP_STORE_INTERVALS[i]['days'] and ((i==len(BACKUP_STORE_INTERVALS)-1) or (int(f.file_timestamp[:8])<=today_ts-BACKUP_STORE_INTERVALS[i+1]['days'])):
                        total_cnt += 1
                exceed_cnt = total_cnt - BACKUP_STORE_INTERVALS[i]['cnt']
                if exceed_cnt<0: 
                    exceed_cnt = 0
                
                DebugLog(context, 'exceed %d - %d' % (i, exceed_cnt))
                
                # check if reserved copy is appropriate to store in current interval
                for f in backup_files:
                    if int(f.file_timestamp[:8])<=today_ts-BACKUP_STORE_INTERVALS[i]['days']:
                        f.del_cnt += 1
                    elif exceed_cnt>0:
                        f.del_cnt = len(BACKUP_STORE_INTERVALS)
                        exceed_cnt -= 1
                    else:
                        break
                i += 1
            
            for f in backup_files:
                DebugLog(context, '%s (%s) - %d' % (f.file_id, f.file_timestamp, f.del_cnt))        
                
            # remove only reserved copies when delete counter match to checked intervals
            for f in backup_files:
                if f.del_cnt >= len(BACKUP_STORE_INTERVALS):
                    f.delete_date = datetime.datetime.now()
                    f.save()
                    DebugLog(context, 'backup file %s deleted' % f.file_id)
                    if not 'del_files' in json_answ:
                        json_answ['del_files'] = []
                    json_answ['del_files'].append(f.file_id)
                
                
    return json_answ

def download_file(context, req):
    if not 'token_id' in req or not 'id' in req:
        DebugLog(context, 'Mandatory tags not found')
        raise HtttpReqError(INV_FORMAT_ANSWER_ERROR, HTTP_REQUEST_ERR)
    
    token_id = req['token_id'].lower()
    if not SESSION_KEY_RE.search(token_id):
        DebugLog(context, 'Invalid token_id format')
        raise HtttpReqError(INV_FORMAT_ANSWER_ERROR, HTTP_REQUEST_ERR)
    
    file_id = req['id'].lower()
    if not FILE_ID_RE.search(file_id):
        DebugLog(context, 'Invalid file_id format')
        raise HtttpReqError(INV_FORMAT_ANSWER_ERROR, HTTP_REQUEST_ERR)

    lock = CF_lock_files.objects.filter(Q(file_id=file_id) & Q(end_date__gte=datetime.datetime.now()))
    if lock:
        DebugLog(context, 'Error active lock found. File blocked file_id=%s' % file_id)
        raise HtttpReqError(DEFAULT_ANSWER_ERROR, HTTP_REQUEST_ERR)

    session = CF_sessions.objects.filter(Q(session_key=token_id) & Q(end_date__gte=datetime.datetime.now()))
    if not session:
        DebugLog(context, 'Error session not found. file_id=%s' % file_id)
        raise HtttpReqError(DEFAULT_ANSWER_ERROR, HTTP_REQUEST_ERR)
    
    session = session[0]
    file_rec = CF_files.objects.filter(Q(file_id=file_id) & Q(delete_date__isnull=True))
    if not file_rec:
        DebugLog(context, 'Error file_id not found')
        raise HtttpReqError(DEFAULT_ANSWER_ERROR, HTTP_REQUEST_ERR)

    file_rec = file_rec[0]
    log = CF_log_access(client_id = session.client_id, action = 'download_file', file_id = file_rec.file_id)
    log.save()
    
    DebugLog(context, 'File found. Check file exits')    
    file_name = os.path.join(CLOUD_FILE_DIR, file_id)
    if not os.path.exists(file_name):
        DebugLog(context, 'Error phisical file not found. file_id=%s' % file_id)
        raise HtttpReqError(DEFAULT_ANSWER_ERROR, HTTP_REQUEST_ERR)

    content = StringIO(file(file_name, "rb").read())
    response = HttpResponse(content.read(), content_type='application/octet-stream')
    response['Content-Disposition'] = 'attachment; filename="%s"' % file_id
    response['Content-Length'] = content.tell()
    DebugLog(context, 'File transfered')    
    return response    
    
def del_file(context, req):
    if not 'token_id' in req or not 'id' in req:
        DebugLog(context, 'Mandatory tags not found')
        raise HtttpReqError(INV_FORMAT_ANSWER_ERROR, HTTP_REQUEST_ERR)
    
    token_id = req['token_id'].lower()
    if not SESSION_KEY_RE.search(token_id):
        DebugLog(context, 'Invalid token_id format')
        raise HtttpReqError(INV_FORMAT_ANSWER_ERROR, HTTP_REQUEST_ERR)
    
    file_id = req['id'].lower()
    if not FILE_ID_RE.search(file_id):
        DebugLog(context, 'Invalid file_id format')
        raise HtttpReqError(INV_FORMAT_ANSWER_ERROR, HTTP_REQUEST_ERR)

    lock = CF_lock_files.objects.filter(Q(file_id=file_id) & Q(end_date__gte=datetime.datetime.now()))
    if lock:
        DebugLog(context, 'Error active lock found. File blocked file_id=%s' % file_id)
        raise HtttpReqError(DEFAULT_ANSWER_ERROR, HTTP_REQUEST_ERR)

    session = CF_sessions.objects.filter(Q(session_key=token_id) & Q(end_date__gte=datetime.datetime.now()))
    if not session:
        DebugLog(context, 'Error session not found. file_id=%s' % file_id)
        raise HtttpReqError(DEFAULT_ANSWER_ERROR, HTTP_REQUEST_ERR)
    
    session = session[0]
    file_rec = CF_files.objects.filter(Q(file_id=file_id) & Q(owner_id=session.client_id))
    if not file_rec:
        DebugLog(context, 'Error file_id not found')
        raise HtttpReqError(DEFAULT_ANSWER_ERROR, HTTP_REQUEST_ERR)

    file_rec = file_rec[0]
    if not file_rec.file_type in ('P','R'):
        DebugLog(context, 'Its possible to delete Private or Reserved file only')
        raise HtttpReqError(DEFAULT_ANSWER_ERROR, HTTP_REQUEST_ERR)
    
    log = CF_log_access(client_id = session.client_id, action = 'del_file', file_id = file_rec.file_id)
    log.save()
        
    file_name = file_rec.file_name
    if file_rec.delete_date==None:
        DebugLog(context, 'File record found. Set delete_date')
        file_rec.delete_date = datetime.datetime.now()
        file_rec.save()
        if file_rec.file_type=='P':
            DebugLog(context, 'Delete reserved copies')
            files = CF_files.objects.filter(Q(parent_file_id=file_id) & Q(owner_id=session.client_id) & Q(delete_date__isnull=True))
            for f in files:
                f.delete_date = datetime.datetime.now()
                f.save()        
    else:
        DebugLog(context, 'File record found. Delete file physicaly')
        dest_file = os.path.join(CLOUD_FILE_DIR, file_rec.file_id)
    
        if os.path.exists(dest_file):
            os.remove(dest_file)
        file_rec.delete()
        
    json_answ = {"answ_code": 0, "name": file_name}
    return json_answ

def check_file(context, req):
    if not 'token_id' in req or not 'id' in req:
        DebugLog(context, 'Mandatory tags not found')
        raise HtttpReqError(INV_FORMAT_ANSWER_ERROR, HTTP_REQUEST_ERR)
    
    token_id = req['token_id'].lower()
    if not SESSION_KEY_RE.search(token_id):
        DebugLog(context, 'Invalid token_id format')
        raise HtttpReqError(INV_FORMAT_ANSWER_ERROR, HTTP_REQUEST_ERR)
    
    file_id = req['id'].lower()
    if not FILE_ID_RE.search(file_id):
        DebugLog(context, 'Invalid file_id format')
        raise HtttpReqError(INV_FORMAT_ANSWER_ERROR, HTTP_REQUEST_ERR)

    session = CF_sessions.objects.filter(Q(session_key=token_id) & Q(end_date__gte=datetime.datetime.now()))
    if not session:
        DebugLog(context, 'Error session not found. file_id=%s' % file_id)
        raise HtttpReqError(DEFAULT_ANSWER_ERROR, HTTP_REQUEST_ERR)
    
    session = session[0]
    file_rec = CF_files.objects.filter(Q(file_id=file_id) & Q(delete_date__isnull=True))
    if not file_rec:
        DebugLog(context, 'Error file_id not found')
        raise HtttpReqError(DEFAULT_ANSWER_ERROR, HTTP_REQUEST_ERR)
    
    file_rec = file_rec[0]
    if file_rec.file_type=="R":
        DebugLog(context, 'Its impossible to get reserved file status')
        raise HtttpReqError(DEFAULT_ANSWER_ERROR, HTTP_REQUEST_ERR)

    log = CF_log_access(client_id = session.client_id, action = 'check_file', file_id = file_rec.file_id)
    log.save()
   
    json_answ = {"answ_code": 0, "id": file_rec.file_id, "ts": file_rec.file_timestamp, "name": file_rec.file_name, "d": file_rec.file_date}
    return json_answ

def rename_file(context, req):
    if not 'token_id' in req or not 'id' in req or not 'name' in req:
        DebugLog(context, 'Mandatory tags not found')
        raise HtttpReqError(INV_FORMAT_ANSWER_ERROR, HTTP_REQUEST_ERR)

    token_id = req['token_id'].lower()
    if not SESSION_KEY_RE.search(token_id):
        DebugLog(context, 'Invalid token_id format')
        raise HtttpReqError(INV_FORMAT_ANSWER_ERROR, HTTP_REQUEST_ERR)
    
    file_id = req['id'].lower()
    if not FILE_ID_RE.search(file_id):
        DebugLog(context, 'Invalid file_id format')
        raise HtttpReqError(INV_FORMAT_ANSWER_ERROR, HTTP_REQUEST_ERR)

    session = CF_sessions.objects.filter(Q(session_key=token_id) & Q(end_date__gte=datetime.datetime.now()))
    if not session:
        DebugLog(context, 'Error session not found. file_id=%s' % file_id)
        raise HtttpReqError(DEFAULT_ANSWER_ERROR, HTTP_REQUEST_ERR)
    
    session = session[0]
    file_rec = CF_files.objects.filter(Q(file_id=file_id) & Q(owner_id=session.client_id) & Q(delete_date__isnull=True))
    if not file_rec:
        DebugLog(context, 'Error file_id not found')
        raise HtttpReqError(DEFAULT_ANSWER_ERROR, HTTP_REQUEST_ERR)

    file_rec = file_rec[0]
    if file_rec.file_type!="P":
        DebugLog(context, 'Its possible to rename private file only')
        raise HtttpReqError(DEFAULT_ANSWER_ERROR, HTTP_REQUEST_ERR)

    file_name = req['name'][:254]
    if not file_name:
        DebugLog(context, 'Error provided empty file name')
        raise HtttpReqError(INV_FORMAT_ANSWER_ERROR, HTTP_REQUEST_ERR)

    log = CF_log_access(client_id = session.client_id, action = 'rename_file', file_id = file_rec.file_id)
    log.save()
    file_rec.file_name = file_name
    file_rec.save()
    json_answ = {"answ_code": 0, "id": file_rec.file_id, "ts": file_rec.file_timestamp, "name": file_rec.file_name, "d": file_rec.file_date}
    return json_answ


def restore_file(context, req):
    if not 'token_id' in req or not 'id' in req:
        DebugLog(context, 'Mandatory tags not found')
        raise HtttpReqError(INV_FORMAT_ANSWER_ERROR, HTTP_REQUEST_ERR)
    
    token_id = req['token_id'].lower()
    if not SESSION_KEY_RE.search(token_id):
        DebugLog(context, 'Invalid token_id format')
        raise HtttpReqError(INV_FORMAT_ANSWER_ERROR, HTTP_REQUEST_ERR)
    
    file_id = req['id'].lower()
    if not FILE_ID_RE.search(file_id):
        DebugLog(context, 'Invalid file_id format')
        raise HtttpReqError(INV_FORMAT_ANSWER_ERROR, HTTP_REQUEST_ERR)

    session = CF_sessions.objects.filter(Q(session_key=token_id) & Q(end_date__gte=datetime.datetime.now()))
    if not session:
        DebugLog(context, 'Error session not found. file_id=%s' % file_id)
        raise HtttpReqError(DEFAULT_ANSWER_ERROR, HTTP_REQUEST_ERR)
    
    session = session[0]
    file_rec = CF_files.objects.filter(Q(file_id=file_id) & Q(owner_id=session.client_id) & Q(delete_date__isnull=False))
    if not file_rec:
        DebugLog(context, 'Error file_id not found')
        raise HtttpReqError(DEFAULT_ANSWER_ERROR, HTTP_REQUEST_ERR)

    file_rec = file_rec[0]
    if file_rec.file_type!="P":
        DebugLog(context, 'Its possible to restore private file only')
        raise HtttpReqError(DEFAULT_ANSWER_ERROR, HTTP_REQUEST_ERR)

    
    log = CF_log_access(client_id = session.client_id, action = 'restore_file', file_id = file_rec.file_id)
    log.save()
    file_rec.delete_date = None
    file_rec.save()
   
    json_answ = {"answ_code": 0, "id": file_rec.file_id, "ts": file_rec.file_timestamp, "name": file_rec.file_name, "d": file_rec.file_date}
    return json_answ

def delete_old_files():
    today = datetime.date.today()
    files = CF_files.objects.filter((Q(delete_date__lte=today - datetime.timedelta(days=RESERVED_STORE_DAYS)) & Q(file_type='R')) | Q(delete_date__lte=today - datetime.timedelta(days=COMMON_STORE_DAYS)))
    for f in files:
        dest_file = os.path.join(CLOUD_FILE_DIR, f.file_id)
    
        if os.path.exists(dest_file):
            os.remove(dest_file)
        f.delete()

@require_http_methods(['POST'])
@csrf_exempt
def cf_api(request, id):
    try:
        size = int(request.META["CONTENT_LENGTH"])
    except:
        size = 0
       
    try:
        context = Context()
        context.debug = settings.DEBUG
        context.ip = request.META["REMOTE_ADDR"][:15]
        context.user = 'auto'
        context.module = 'cloud_files' 
        
        if context.debug:
            ClearDebugLog(context)

        req_body = request.body[:size]

        if 'req' in request.POST:
            DebugLog(context, 'POST form field "req" detect')
            req_body = request.POST['req']
        else:
            DebugLog(context, 'POST raw body detect')
           # return HttpResponseNotFound()
            #DebugLog(context, str(request.POST))
            #req_body = request.body
            
        try:
            json_req = json.JSONDecoder().decode(req_body)
        except:
            DebugLog(context, 'ERROR cf_api json format: %s' % req_body)
            return HttpResponseNotFound()
                
        DebugLog(context, 'Start process cloud files action id=%s' % id)


        if id=='get_token':
            # first client authorization and request session token_id. Request private keys 
            json_answ = get_token(context, json_req)
        elif id=='file_list':
            # retrieve file list for client' session
            json_answ = file_list(context, json_req)
        elif id=='upload_req':
            # request to upload file. generate file_id and timestamp
            json_answ = upload_req(context, json_req)
        elif id=='upload_file' and 'uploadedfile' in request.FILES:
            # upload file
#            return HttpResponseNotFound()
            json_answ = upload_file(context, json_req, request.FILES['uploadedfile'])
        elif id=='download_file':
            # download file
            return download_file(context, json_req)
        elif id=='del_file':
            # request to upload file. generate file_id and timestamp
            json_answ = del_file(context, json_req)
        elif id=='check_file':
            # check actual timestamp for specified file_id
            json_answ = check_file(context, json_req)
        elif id=='show_trash':
            # show deleted files in trash
            json_answ = show_trash(context, json_req)
        elif id=='restore_file':
            # restore file from trash
            json_answ = restore_file(context, json_req)
        elif id=='rename_file':
            # rename private file
            json_answ = rename_file(context, json_req)
        else:
            DebugLog(context, 'Unsupported action: %s' % id)
            raise HtttpReqError(u'Unknown function', HTTP_REQUEST_ERR)

        return JSONResponse(json_answ)
                         
    except HtttpReqError, e:
        json_answ = {"answ_code": 1, "error": e.message}
        return HttpResponse(json.dumps(json_answ), content_type="application/json")        
    except MySQLdb.Error, e:
        SystemLog('ERROR DB cf_api (%s): %s; %s' % (id, e.__class__, e.args))
        json_answ = {"answ_code": 2, "error": 'database error'}
        return JSONResponse(json_answ)        
    except Exception, e:
        SystemLog('ERROR SYSTEM cf_api (%s): %s; %s' % (id, e.__class__, e.args))
        json_answ = {"answ_code": 3, "error": 'system error'}
        return JSONResponse(json_answ)             
