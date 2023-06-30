import nmap

def scan_network():
  # crea un objeto de sacando
  nm = nmap.PortScanner()


  # especifica el rango
  ip_range = "192.168.5.1/24"


  nm.scan(hosts=ip_range, arguments='-sn')


  # recorre los resultados
  for host in nm.all_host():
    if 'mac' in nm[host]['adresses']:
      ip = nm[host]['adresses']['ipv4']
      mac = nm[host]['adresses']['mac']

      print("IP: ", ip)
      print("MAC: ", mac)
      
scan_network()
