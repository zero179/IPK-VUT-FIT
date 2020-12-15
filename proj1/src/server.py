import socket
import re
import sys

if (len(sys.argv)!=2):
    sys.exit('INVALID NUMBER OF ARGUMENTS')

HOST = '127.0.0.1'  # Standard loopback interface address (localhost)
PORT = int(sys.argv[1])
try:
    PORT = int(sys.argv[1])
except:
    sys.exit('ITS WRONG')

if (PORT<0 or PORT > 65535):
    sys.exit('INVALID PORT')
    
with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR,1)
    s.bind((HOST, PORT))
    while True:
        request_200 = '200 OK\r\n\r\n'
        request_404 = '404 Not Found\r\n\r\n'
        request_400 = '400 Bad Request\r\n\r\n'
        request_405 = '405 Method Not Allowed\r\n\r\n'
        request_500 = '500 Internal Server Error\r\n\r\n'
        http = 'HTTP/1.1 '
        s.listen()
        conn, addr = s.accept()
        with conn:
            
            data = conn.recv(1024)
            data=data.decode('utf-8')
            post_riad = data
            pom_riad = post_riad.split('\r\n')
                
            pom_riad_2 = pom_riad[0].split()
            pom=pom_riad_2

            if ( pom[0] != 'GET' and pom[0]!= 'POST'):
                http = http.encode('utf-8')
                request_405 = request_405.encode('utf-8')
                response = http + request_405
                conn.sendall(response)
                response = ''
                conn.close()
                continue
                
            elif not re.fullmatch('GET \/resolve\?name=(.+?)&type=(A|PTR) HTTP\/1.1', pom_riad[0]) and not re.fullmatch('GET \/resolve\?type=(A|PTR)&name=(.+?) HTTP\/1.1', pom_riad[0]) and not re.fullmatch('POST \/dns-query HTTP\/1.1', pom_riad[0]):
            
                http = http.encode('utf-8')
                request_400 = request_400.encode('utf-8')
                response = http + request_400
                conn.sendall(response)
                response = ''
                conn.close()
                continue
                
            elif (pom[2] != 'HTTP/1.1' ):
                http = http.encode('utf-8')
                request_400 = request_400.encode('utf-8')
                response = http + request_400
                conn.sendall(response)
                response = ''
                conn.close()
                continue
                
            elif (pom[0] == 'GET'):
                pom_1=pom[1].split('?')
             
                if (pom_1[0] != '/resolve'):
                    http = http.encode('utf-8')
                    request_400 = request_400.encode('utf-8')
                    response = http + request_400
                    conn.sendall(response)
                    response = ''
                    conn.close()
                    continue
                else:
                    pom_2=pom_1[1].split('=')
                
                    if (pom_2[0] != 'name' and pom_2[0] !='type'):
                        http = http.encode('utf-8')
                        request_400 = request_400.encode('utf-8')
                        response = http + request_400
                        conn.sendall(response)
                        response = ''
                        conn.close()
                        continue
                        
                    elif (pom_2[2] != 'A' and pom_2[2] != 'PTR'):
                        http = http.encode('utf-8')
                        request_400 = request_400.encode('utf-8')
                        response = http + request_400
                        conn.sendall(response)
                        response = ''
                        conn.close()
                        continue
                    
                    else:
                        amperesand = pom_2[1]
                        amperesand=amperesand.split('&')
                        if (amperesand[1] != 'type' and 'name'):
                            http = http.encode('utf-8')
                            request_400 = request_400.encode('utf-8')
                            response = http + request_400
                            conn.sendall(response)
                            response = ''
                            conn.close()
                            continue
                        
                        else:
                            cislo = socket.gethostbyname(amperesand[0])
                            vypis = 'HTTP/1.1 ' + request_200 + amperesand[0] + ':' + pom_2[2] + '=' + cislo + '\r\n'
                            vypis = vypis.encode('utf-8')
                            conn.sendall(vypis)
                            vypis = ''
                            conn.close()
                            continue
            
            elif (pom[0] == 'POST'):
                if (pom[2] != 'HTTP/1.1'):
                    http = http.encode('utf-8')
                    request_400 = request_400.encode('utf-8')
                    response = http + request_400
                    conn.sendall(response)
                    response = ''
                    conn.close()
                    continue
                    
                elif (pom[1] != '/dns-query'):
                    http = http.encode('utf-8')
                    request_400 = request_400.encode('utf-8')
                    response = http + request_400
                    conn.sendall(response)
                    response = ''
                    conn.close()
                    continue
                else:
                    pom_riad2 = pom_riad[7].split('\n')
                    length=len(pom_riad2)
                    vypis_2 = ''
                    for i in range(length):
                        pom_colon =pom_riad2[i].split(':')
                        if pom_colon[1] == 'A':
                            adresa = socket.gethostbyname(pom_colon[0])
                            vypis_2 +=  pom_colon[0] + ':' + pom_colon[1] + '=' + adresa + '\r\n'
                            
                        elif (pom_colon[1] == 'PTR'):
                            meno = socket.gethostbyaddr(pom_colon[0])[0]
                            vypis_2 += pom_colon[0] + ':' + pom_colon[1] + '=' + meno + '\r\n'
                        
                        else:
                            http = http.encode('utf-8')
                            request_400 = request_400.encode('utf-8')
                            response = http + request_400
                            conn.sendall(response)
                            response = ''
                            conn.close()
                            continue
                    
                    vypis_2 = http + request_200 + vypis_2
                    vypis_2 = vypis_2.encode('utf-8')
                    conn.sendall(vypis_2)
                    vypis_2 = ''
                    conn.close()
                    continue
            if not data:
                break
            
            
