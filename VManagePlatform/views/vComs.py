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
        
    vmList = VmServer.objects.all().order_by("-id")
    inStanceList = []
    SERV=["test"]
    count=0
    count2=0
    for vm in vmList:
        try:
            vServer = VmServer.objects.get(id=str(vm.id))
        except:
            return render_to_response('404.html',context_instance=RequestContext(request))
        
# Checking closed hosts. 
        try:
            rVMS = LibvirtManage(vServer.server_ip,vServer.username, vServer.passwd, vServer.vm_type)
            rSERV= rVMS.genre(model='server')            
            rVMS.close()
            VmInfo = rSERV.getVmServerInfo()
        except Exception as e:
            inStanceList+={'status': 0},
            inStanceList[count]['hostname']=vm.hostname
            inStanceList[count]['hserver_ip']=vm.server_ip
            inStanceList[count]['hstatus']=1
            inStanceList[count]['id']=vm.id
            inStanceList[count]['hInfo']={'cpu_total':"None",'mem':"None"}
            count+=1
            continue

        try:
            VMS = LibvirtManage(vServer.server_ip,vServer.username, vServer.passwd, vServer.vm_type)
            SERVER = VMS.genre(model='server')
            VMS.close()
            userList = User.objects.all()    
            if SERVER:
                inStanceList2 = SERVER.getVmInstanceBaseInfo(server_ip=vServer.server_ip,server_id=vServer.id)
                inStanceList+=inStanceList2 
                for ll in inStanceList2:
                    if inStanceList[count]['server_ip']==vmList[count2].server_ip:
                        pass
                    else:
                        count2+=1
                    inStanceList[count]['hostname']=vmList[count2].hostname
                    inStanceList[count]['hserver_ip']=vmList[count2].server_ip
                    inStanceList[count]['cpu_total']=vmList[count2].cpu_total
                    inStanceList[count]['mem']=vmList[count2].mem
                    inStanceList[count]['instance']=vmList[count2].instance
                    inStanceList[count]['hstatus']=vmList[count2].status
                    inStanceList[count]['id']=vmList[count2].id
                    inStanceList[count]['hInfo']=VmInfo
                    count+=1

                VMS.close()
            else:return render_to_response('404.html',context_instance=RequestContext(request))
            # listinstanca done
        except:
            inStanceList = None
        
        # info
        '''
        try:
            VMS = LibvirtManage(vServer.server_ip,vServer.username, vServer.passwd, vServer.vm_type)
            INSTANCE = VMS.genre(model='instance')
            if INSTANCE:
                for ll in inStanceList2:
                    instance = INSTANCE.queryInstance(name=str(ll['name']))
                    insInfo = INSTANCE.getVmInstanceInfo(instance,server_ip=ll['server_ip'],vMname=ll['name'])
                    insInfo['cpu_per'] = INSTANCE.getCpuUsage(instance)

                    inStanceList[count]['inStance']=insInfo
                    count+=1
                    VMS.close()
            else:return render_to_response('404.html',context_instance=RequestContext(request))
        except:
            insInfo = None
        '''
    return render_to_response('vmInstance/all_instance.html',{"user":request.user,"localtion":[{"name":"Home","url":'/'},{"name":"Virtual machine instance","url":'#'},{"name":"List of virtual machine instances","url":"/%d/" % vServer.id}],
                                            "inStanceList":inStanceList,"vmServer":vServer,"userList":userList,"SERV":SERV},
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