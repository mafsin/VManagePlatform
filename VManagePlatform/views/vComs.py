#!/usr/bin/env python  
# _#_ coding:utf-8 _*_  

from django.conf import settings
from django.http import HttpResponseRedirect
from django.shortcuts import render_to_response,render
from django.contrib import auth
from django.template import RequestContext
from django.contrib.auth.decorators import login_required
from VManagePlatform.models import VmServer,VmServerInstance
from VManagePlatform.utils.vConnUtils import TokenUntils
from VManagePlatform.models import VmLogs

import time
from VManagePlatform.utils.vMConUtils import LibvirtManage
from VManagePlatform.const import Const 
from VManagePlatform.utils.vConnUtils import CommTools
from VManagePlatform.tasks import migrateInstace,cloneInstace,recordLogs
from VManagePlatform.utils.vBrConfigUtils import BRManage
from django.contrib.auth.models import User

@login_required(login_url='/login')
def index(request):
    vmRun = 0
    vmStop = 0
    serRun = 0
    serStop = 0
    try:
        logList = VmLogs.objects.all().order_by("-id")[0:20]
        vmList = VmServer.objects.all().order_by("-id")
        serList = VmServerInstance.objects.all().order_by("-id")
        for vm in vmList:
            if vm.status == 1:vmRun = vmRun + 1
            else:vmStop = vmStop + 1
        for ser in serList:
            if ser.status == 0:serRun = serRun + 1
            else:serStop = serStop + 1
    except:
        logList = None
        vmList = []
        serList = []
    totalInfo = {"vmRun":vmRun,"vmStop":vmStop,"serTotal":len(serList),
                 "serStop":serStop,"vmTotal":len(vmList),"serRun":serRun}
    return render_to_response('index.html',{"user":request.user,"localtion":[{"name":"Home","url":'/'}],
                                            "logList":logList,"totalInfo":totalInfo,"msgTotal":serStop+vmStop},
                              context_instance=RequestContext(request))
'''
TEST ALANI BASLANGICI
'''
@login_required(login_url='/login')
def allInstance(request):
    vmRun = 0
    vmStop = 0
    serRun = 0
    serStop = 0
    # test icin olusturuldu sil alttaki 
    SERV=""
    try:
        logList = VmLogs.objects.all().order_by("-id")[0:20]
        vmList = VmServer.objects.all().order_by("-id")
        serList = VmServerInstance.objects.all().order_by("-id")
        for vm in vmList:
            if vm.status == 1:vmRun = vmRun + 1
            else:vmStop = vmStop + 1

        for ser in serList:
            if ser.status == 0:serRun = serRun + 1
            else:serStop = serStop + 1
    except:
        logList = None
        vmList = []
        serList = []
    
    
    vmLt = VmServer.objects.all().order_by("-id")
    inStanceList3 = []
    for vm in vmLt:
        try:
            # test icin olusturuldu sil alttaki
            # SERV+=":"+vm.server_ip+";"
            id=vm.server_ip
            SERV+="/"+str(vm.id)+"/"
            vServer = VmServer.objects.get(id=str(vm.id))
            # vServer = VmServer.objects.get(id=id)
        except:
            return render_to_response('404.html',context_instance=RequestContext(request))
            
        try:
            VMS = LibvirtManage(vServer.server_ip,vServer.username, vServer.passwd, vServer.vm_type)    
            SERVER = VMS.genre(model='server')
            VMS.close()
            userList = User.objects.all()    
            if SERVER:
                inStanceList2 = SERVER.getVmInstanceBaseInfo(server_ip=vServer.server_ip,server_id=vServer.id)
                # inStanceList3 = isinstance(inStanceList2,list)
                inStanceList3+=inStanceList2 
                VMS.close()
            else:return render_to_response('404.html',context_instance=RequestContext(request))
            # listinstanca done
        except:
            inStanceList2 = None
        
    totalInfo = {"vmRun":vmRun,"vmStop":vmStop,"serTotal":len(serList),
                 "serStop":serStop,"vmTotal":len(vmList),"serRun":serRun,"SERV":SERV}
    
    # test icin olusturuldu sil usettki, orj altta 
    # totalInfo = {"vmRun":vmRun,"vmStop":vmStop,"serTotal":len(serList),
                 # "serStop":serStop,"vmTotal":len(vmList),"serRun":serRun}
    return render_to_response('vmInstance/all_instance.html',{"user":request.user,"localtion":[{"name":"Home","url":'/'},{"name":"Virtual machine instance","url":'#'},{"name":"List of virtual machine instances","url":"/%d/" % vServer.id}],
                                            "logList":logList,"totalInfo":totalInfo,"msgTotal":serStop+vmStop,"dataList":vmList,"inStanceList2":inStanceList2,"inStanceList3":inStanceList3,"vmServer":vServer,"userList":userList},
                              context_instance=RequestContext(request))

'''
TEST ALANI BITISI
'''

def login(request):
    if request.session.get('username') is not None:
        return HttpResponseRedirect('/profile',{"user":request.user})
    else:
        username = request.POST.get('username')
        password = request.POST.get('password') 
        user = auth.authenticate(username=username,password=password)
        if user and user.is_active:
            auth.login(request,user)
            request.session['username'] = username
            return HttpResponseRedirect('/profile',{"user":request.user})
        else:
            if request.method == "POST":
                return render_to_response('login.html',{"login_error_info":"The username is good, or the password is wrong!"},
                                                        context_instance=RequestContext(request))  
            else:
                return render_to_response('login.html',context_instance=RequestContext(request)) 


          
@login_required
def permission(request,args=None):
    return render_to_response('noperm.html',{"user":request.user},
                                  context_instance=RequestContext(request))    

        
@login_required
def run_vnc(request,id,vnc,uuid):
    '''
        Call the VNC proxy for remote control
    '''
    vServer = VmServer.objects.get(id=id)
    tokenStr = uuid + ': ' + vServer.server_ip + ':' + str(vnc)
    TokenUntils.writeVncToken(filename=uuid,token=tokenStr) 
    return render(request, 'vnc/vnc_auto.html',{"vnc_port":settings.VNC_PROXY_PORT,
                                                    "vnc_token":uuid,
                                                    })


def logout(request):
    auth.logout(request)
    return HttpResponseRedirect('/login')