import sys
import clsConfig
import tenable.sc
import pprint
import collections

CONF=clsConfig.Configuration(r'config.cfg',)
CONF.prepConfig()

try:
  apiAccess=CONF.getParam('API SC','access')
  apiSecret=CONF.getParam('API SC','secret')
  host=CONF.getParam('API SC','server')
  scptbn= tenable.sc.TenableSC(host,apiAccess,apiSecret)
  listscandetails=[]

  '''
  Prints a text file separated by | with agent_id, dns name, netbios name, operating system, MAC address and IP address
  by the scan name.

  Useful to extract the network interfaces in Windows Systems.

  Uses Tenable Plugin ID 24272  Network Interfaces Enumeration (WMI)

  '''

  def getWindowsIPv4By24272(lowerstring):

    for scan in scptbn.scan_instances.list()['manageable']:
      listid=[]
      lowerstring=lowerstring.lower()
      name=scan['name'].lower()
      if lowerstring in name:
        for idscan in scptbn.scan_instances.list()['manageable']:
          if name in idscan['name'].lower():
            listid.append(idscan['id'])
        listscandetails.append(max(listid))

    scansid=list(collections.OrderedDict.fromkeys(listscandetails))

    ipliststr=[]

    for scan in scansid:
      for vuln in scptbn.analysis.scan(scan,('pluginID','=','24272')):

        output=vuln['pluginText']
        idx=output.find('Routing')
        preiplist=output[0:idx].split('-')
        
        for stripcomp in preiplist:
          if 'IPAddress' in stripcomp:
            ipstr1=stripcomp.split(' IPAddress/IPSubnet = ')
            idx=ipstr1[1].find('/')
            ip=ipstr1[1][0:idx].strip()
            ipliststr.append(ip)

            dns=vuln['dnsName']
            mac=vuln['macAddress']
            ntbios=vuln['netbiosName']
            OS=vuln['operatingSystem']
            agent=vuln['uuid']

            print(agent+'|'+dns+'|'+ntbios+'|'+OS+'|'+mac+'|'+ip)

  '''
  Prints a text file separated by | with agent_id, dns name, netbios name, operating system, MAC address and IP address
  by the scan name.

  Useful to extract the network interfaces in Unix Systems.

  Uses Tenable Plugin ID 25203 # Enumerate IPv4 Interfaces via SSH (25203)

  '''

  def getUNIXIPv4By25203(lowerstring):

    for scan in scptbn.scan_instances.list()['manageable']:
      listid=[]
      lowerstring=lowerstring.lower()
      name=scan['name'].lower()
      if lowerstring in name:
        for idscan in scptbn.scan_instances.list()['manageable']:
          if name in idscan['name'].lower():
            listid.append(idscan['id'])
        listscandetails.append(max(listid))

    scansid=list(collections.OrderedDict.fromkeys(listscandetails))

    ipliststr=[]
    ethliststr=[]
   
    for scan in scansid:
      for vuln in scptbn.analysis.scan(scan,('pluginID','=','25203')):

        output=vuln['pluginText']
        idx=output.find('\n</plugin_output>')
        preiplist=output[0:idx].split('-')
        
        for stripcomp in preiplist:
          if 'interface' in stripcomp:
            ipstr1=stripcomp.split('on')
            idx=ipstr1[0].find('(')
            ip=ipstr1[0][0:idx].strip()
            ipliststr.append(ip)

            ipstr2=stripcomp.split('interface')
            idx=ipstr2[1].find(')')
            intf=ipstr2[1][0:idx].strip()
            ethliststr.append(intf)

            dns=vuln['dnsName']
            mac=vuln['macAddress']
            OS=vuln['operatingSystem']
            agent=vuln['uuid']

            print(agent+'|'+dns+'|'+intf+'|'+OS+'|'+mac+'|'+ip)

  def getPatchInfo(lowerstring,listTigo=None):
    listremed=[]
    
    if listTigo is not None:
      print('Excluir lista de agent_id')

    csvfile=open('patch.csv','w+')
    csvfile.write('solution|remediation|score|vpr|ip|dns|ntbios|OS|cpe|mac|agent|repository\n')
  
    for remed in scptbn.analysis.vulns(('repositoryIDs','=','9,2,8,3,10,1,12,11'),tool='sumremediation'):
      pid=remed['pluginID']
      for vulns in scptbn.analysis.vulns(('repositoryIDs','=','9,2,8,3,10,1,12,11'),('pluginID','=',pid),tool='vulndetails'):
        cpe=remed['cpe']
        solution=remed['solution'].replace('\n',' ')
        remediation=remed['remediationList']
        score=remed['score']
        vpr=remed['vprScore']
        ip=vulns['ip']
        dns=vulns['dnsName']
        mac=vulns['macAddress']

        if vulns['operatingSystem']:
          OS=vulns['operatingSystem']
        else:
          OS=''
        
        ntbios=vulns['netbiosName']
        
        if vulns['uuid']:
          agent=vulns['uuid']
        else:
          agent='No Agent'

        arrrepo=vulns['repository']
        repo=arrrepo['name']
        #print(cpe+'|'+solution+'|'+remediation+'|'+score+'|'+vpr+'|'+ip+'|'+dns+'|'+ntbios+'|'+OS+'|'+mac+'|'+agent+'|'+repo)
        csvfile.writelines([solution+'|',remediation+'|',score+'|',vpr+'|',ip+'|',dns+'|',ntbios+'|',OS+'|',cpe+'|',mac+'|',agent+'|',repo+'\n'])
      listremed.append(remed)
    csvfile.close()

  '''
  Prints a text file separated by | with IP address, dns name, netbios name, MAC address, operating system, user, user or group,
  plugin_id, agent_id, and repository by a string with repository id separated with comma Example '2,4,15'

  Useful to extract the users and groups with administrative rights in a repository with Windows Systems.

  Uses Tenable Plugin ID 10902 # Microsoft Windows 'Administrators' Group User List

  '''

  def getAdminGroupsByStation10902(repo=None):
    if repo is not None:
      try:
        repo.split(",")
      except Exception as e:
        print('Exception '+str(e))
        sys.exit(0)

    csvfile=open('AdminGroupsByStation.csv','w+')
    csvfile.write('ip|dns|ntbios|mac|OS|user|pid|agent|repository\n')
    
    for admins in scptbn.analysis.vulns(('repositoryIDs','=',repo),('pluginID','=','10902')):
      pid=admins['pluginID']
      ip=admins['ip']
      dns=admins['dnsName']
      ntbios=admins['netbiosName']
      mac=admins['macAddress']

      if admins['operatingSystem']:
        OS=admins['operatingSystem']
      else:
        OS=''

      if admins['uuid']:
        agent=admins['uuid']
      else:
        agent='No Agent'

      arrrepo=admins['repository']
      repo=arrrepo['name']

      output=admins['pluginText']
      idx=output.find('group :\n\n')
      offset=idx+9
      preadminlist=output[offset:len(output)].split('-')
      
      for stripcomp in preadminlist:
        if ('User' in stripcomp or 'Group' in stripcomp):
          usertmp=stripcomp.split('(')
          user=usertmp[0].strip(' ')

          if 'User' in stripcomp:
            typeE='User'
          elif 'Group' in stripcomp:
            typeE='Group'
          else:
            typeE='Null'

          print(ip+'|'+dns+'|'+ntbios+'|'+mac+'|'+OS+'|'+user+'|'+typeE+'|'+pid+'|'+agent+'|'+repo)
          csvfile.writelines([ip+'|'+dns+'|'+ntbios+'|'+mac+'|'+OS+'|'+user+'|'+typeE+'|'+pid+'|'+agent+'|'+repo+'\n'])
          
    csvfile.close()
  
  #getWindowsIPv4By24272("MAQUINAS")
  #getUNIXIPv4By25203("SERVIDORES")
  #listipTigo=[0.0.0.0]
  #getPatchInfo("SERVIDORES",listipTigo)

  getAdminGroupsByStation10902('4,14')

except Exception as e:
  print('Exception '+str(e))
  sys.exit(0)


