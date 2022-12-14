# -*- coding: utf-8 -*-
'''
models.py
Production version:  1  (01.06.2016) 
@author: Ivan Diakonenko
'''

from django.db import models
from django.db.models.query import Q

TEST_MANAGED_ATTR = False 

class Cert_online(models.Model):
    cert_id = models.CharField(max_length=10, primary_key=True) 
    client_id = models.IntegerField() 
    lic_num = models.CharField(max_length=13) 
    sys_id = models.CharField(max_length=10) 
    prg_id = models.CharField(max_length=11) 
    act_date = models.DateTimeField() 
    last_date = models.DateTimeField() 
    check_cnt = models.IntegerField() 
    confirm_date = models.DateTimeField()  
    confirm_cure = models.IntegerField()  
    comp_id = models.CharField(max_length=50)
    last_ver = models.CharField(max_length=15)
    class Meta:
       managed = TEST_MANAGED_ATTR
       #unique_together = ('client_id',)
       db_table = 'cert_online'    

class CF_clients_keys(models.Model):
     #id by default
    client = models.ForeignKey('Clients', db_column='client_id', on_delete=models.CASCADE)
    key = models.ForeignKey('CF_rsakeys', db_column='key_id', on_delete=models.CASCADE)
    default = models.IntegerField()
    class Meta:
       managed = False
       unique_together = ('client','key')
       db_table = 'cf_clients_keys'

class CF_files(models.Model):
    file_id = models.CharField(max_length=12, primary_key=True)
    file_timestamp = models.CharField(max_length=14)
    file_type = models.CharField(max_length=1)   # P - private, E - file to exchange, C - Common file (readonly), R - reserve backup copy
    parent_file_id = models.CharField(max_length=12, blank=True, null=True)
    file_name = models.CharField(max_length=255)
    file_date = models.DateTimeField() # local file datetime 
    owner_id = models.IntegerField()   # --> Clients.client_id
    create_date = models.DateTimeField()
    update_date = models.DateTimeField()
    file_size = models.IntegerField()
    delete_date = models.DateTimeField(blank=True, null=True) 
    class Meta:
       managed = False
       db_table = 'cf_files'
       
class CF_lock_files(models.Model):
    file_id = models.CharField(max_length=12, primary_key=True)
    session_key = models.CharField(max_length=40)
    file_timestamp = models.CharField(max_length=14, blank=True, null=True)
    file_type = models.CharField(max_length=1, blank=True, null=True)
    parent_file_id = models.CharField(max_length=12, blank=True, null=True)
    file_name = models.CharField(max_length=255, blank=True, null=True)
    file_date = models.DateTimeField()
    owner_id = models.IntegerField()   # --> Clients.client_id
    end_date = models.DateTimeField()
    class Meta:
       managed = False
       db_table = 'cf_lock_files'       
           
class CF_rsakeys(models.Model):
    #id by default
    privkey_hex = models.CharField(max_length=1000)
    pubkey_hex = models.CharField(max_length=300)
    create_date = models.DateTimeField()
    desc = models.CharField(max_length=100, blank=True, null=True)
    class Meta:
       managed = False
       db_table = 'cf_rsakeys'
    
class CF_sessions(models.Model):
    session_key = models.CharField(max_length=40, primary_key=True)
    end_date = models.DateTimeField()
    client_id = models.IntegerField()
    class Meta:
       managed = False
       db_table = 'cf_sessions'
       
class CF_log_access(models.Model):
    #id by default
    log_date = models.DateTimeField()
    client_id = models.IntegerField()
    action = models.CharField(max_length=20)    
    file_id = models.CharField(max_length=12, blank=True, null=True)
    class Meta:
       managed = False
       db_table = 'cf_log_access'

class Clients(models.Model):
    client_id = models.AutoField(primary_key=True)
    email = models.CharField(max_length=100, unique=True)
    org_name = models.CharField(max_length=100)
    contact_name = models.CharField(max_length=100, default=u'')
    city = models.CharField(max_length=100)
    country = models.CharField(max_length=50)
    lang_id = models.CharField(max_length=3)
    create_date = models.DateTimeField()
    confirmed = models.IntegerField()
    confirm_code = models.CharField(max_length=20, blank=True, null=True)
    user_id = models.CharField(max_length=20) 
    last_online = models.DateTimeField()

    # calculated field - last used product
    @property
    def calc_last_product(self):
        sort = ('-act_date', '-prod_id')
        rows = Lic_online.objects.filter(Q(client_id=self.client_id) &
                                         Q(prod_id__gte=4) &
                                         Q(act_date__isnull=False)).order_by(*sort)
        if rows:
            return rows[0].prod_id
    
    class Meta:
       managed = TEST_MANAGED_ATTR
       #unique_together = ('client_id',)
       db_table = 'clients'

class Countries(models.Model):
    #id by default
    cnt_id = models.IntegerField()
    lang_id = models.CharField(max_length=3)
    name = models.CharField(max_length=150)
    important = models.SmallIntegerField()
    class Meta:
       managed = TEST_MANAGED_ATTR
       db_table = 'countries'              
              
class Clients_logs(models.Model):
    #id by default
    client_id = models.IntegerField()
    act_date = models.DateTimeField()
    user_id = models.CharField(max_length=20) 
    prop_name = models.CharField(max_length=100)
    prev_value = models.CharField(max_length=100)
    new_value = models.CharField(max_length=100)
    class Meta:
       managed = TEST_MANAGED_ATTR
       db_table = 'clients_logs'
       
class Clients_props(models.Model):
    #id by default
    client_id = models.IntegerField()
    prop_type = models.CharField(max_length=30) 
    prop_name = models.CharField(max_length=100)
    prop_value = models.CharField(max_length=300)
    class Meta:
       managed = TEST_MANAGED_ATTR
       db_table = 'clients_props'              
       
class Prop_types(models.Model):       
    prop_type = models.CharField(max_length=30, primary_key=True) 
    prop_name = models.CharField(max_length=100)
    icon_file = models.CharField(max_length=100)
    class Meta:
       managed = TEST_MANAGED_ATTR
       db_table = 'prop_types'      
    
class Clients_comment(models.Model):
    #id by default
    client_id = models.IntegerField()
    act_date = models.DateTimeField()
    user_id = models.CharField(max_length=20) 
    comment = models.CharField(max_length=1000)
    class Meta:
       managed = TEST_MANAGED_ATTR
       db_table = 'clients_comment'      

class Frames(models.Model):
    name = models.CharField(max_length=30, primary_key=True)
    html_template = models.CharField(max_length=30)
    single = models.IntegerField()
    tab_caption = models.CharField(max_length=50)
    show_selector = models.IntegerField()
    icon_name = models.CharField(max_length=30)
    menu_order = models.IntegerField()
    class Meta:
       managed = TEST_MANAGED_ATTR
       db_table = 'frames'
       ordering = ["menu_order"]

class Dialogs(models.Model):
    name = models.CharField(max_length=30, primary_key=True)
    html_template = models.CharField(max_length=30)
    class Meta:
       managed = TEST_MANAGED_ATTR
       db_table = 'dialogs'
       
class Languages(models.Model):
    lang_id = models.CharField(max_length=3, primary_key=True)
    name = models.CharField(max_length=30)
    class Meta:
       managed = TEST_MANAGED_ATTR
       db_table = 'languages'

class Lic_online(models.Model):
    lic_num = models.CharField(max_length=13, primary_key=True)
    client_id = models.IntegerField()
    prod_id = models.IntegerField(blank=True, null=True)
    lang_id = models.CharField(max_length=3)
    create_date = models.DateTimeField()
    user_id = models.CharField(max_length=20)
    act_date = models.DateTimeField()
    period = models.IntegerField()
    start_date = models.DateTimeField()
    end_date = models.DateTimeField()
    permissions = models.CharField(max_length=10)
    item_cnt = models.IntegerField()
    # calculated field - quantity of used work places
    @property
    def calc_real_cnt(self):
        return len(Cert_online.objects.filter(Q(client_id=self.client_id) & 
                                              Q(lic_num=self.lic_num) & 
                                              Q(act_date__isnull=False)))
    class Meta:
       managed = TEST_MANAGED_ATTR
       db_table = 'lic_online'    
              
class Log_error(models.Model):
    #id by default
    log_date = models.DateTimeField()
    prod_id = models.IntegerField(blank=True, null=True)
    module = models.CharField(max_length=15)
    msg = models.CharField(max_length=100)
    class Meta:
       managed = TEST_MANAGED_ATTR
       db_table = 'log_error'
       ordering = ['-id'] 
                         
class Products(models.Model):
    prod_id = models.IntegerField(primary_key=True)
    name = models.CharField(max_length=30)
    reg_type = models.IntegerField()  # 0 -old type, 1 - new type 6.x
    class Meta:
       managed = TEST_MANAGED_ATTR
       db_table = 'products'

class Permissions(models.Model):
    #id by default
    name = models.CharField(max_length=50)
    rus_name = models.CharField(max_length=50)
    codename = models.CharField(max_length=100)
    admin = models.IntegerField()
    class Meta:
       managed = TEST_MANAGED_ATTR
       db_table = 'permissions'
       
class OrderJSONReq(models.Model):
    #id by default
    req_time = models.DateTimeField()
    email = models.CharField(max_length=100)
    client_id = models.IntegerField(blank=True, null=True)
    org_name = models.CharField(max_length=100)
    contact_name = models.CharField(max_length=100, blank=True, null=True)
    city = models.CharField(max_length=200, blank=True, null=True)
    country = models.CharField(max_length=50, blank=True, null=True)
    lang_id = models.CharField(max_length=3)
    order_num = models.CharField(max_length=20, blank=False, null=False)
    order_item = models.CharField(max_length=200, blank=False, null=False)
    order_amt = models.FloatField()
    order_cur = models.SmallIntegerField(blank=False, null=False)
    prod_id = models.IntegerField(blank=True, null=True)
    period = models.IntegerField(blank=True, null=True)
    permissions = models.CharField(max_length=10, blank=True, null=True)
    item_cnt = models.IntegerField(blank=True, null=True)
    complete_time = models.DateTimeField(blank=True, null=True)
    status = models.SmallIntegerField(blank=False, null=False) # 1 default
    class Meta:
       managed = False
       db_table = 'order_json_req'   
    
