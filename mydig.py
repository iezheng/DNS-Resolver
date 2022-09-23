import dns
import dns.resolver
import time
from datetime import datetime

rdtype = "A"  # global rdtype of A
rdclass = "IN"  # global rdclass of IN
timeout = 3  # global timeout for each protocol
rootServer = ['198.41.0.4', '199.9.14.201', '192.33.4.12',
              '199.7.91.13', '192.203.230.10', '192.5.5.241', '92.112.36.4',
              '198.97.190.53', '192.36.148.17', '192.58.128.30', '193.0.14.129', '199.7.83.42', '202.12.27.33']  # global list of root servers


def main():
    domainName = input("Enter a domain name: ")  # asking user for input
    start = time.time()  # start tracking time
    now = datetime.now()  # tracks the time when request is sent

    file = open("mydig_output", "a")  # opens the mydig_output file
    file.write("Domain Name: " + domainName)  # write input to filed
    # modding input to Absolute form and removing www. since it end up in same ip address
    if not domainName.endswith("."):
        domainName += "."
    query = dns.message.make_query(domainName, rdtype, rdclass)
    if(domainName.startswith("www.")):
        domainName = domainName.replace('www.', '', 1)

    # expect domain name to be false until successfully obtain response
    validDomainName = False

    for nameRootServer in rootServer:
        try:
            finalResponse = dnsResolver(domainName, nameRootServer)
            finalResponse.answer[0]
            validDomainName = True
            print("QUESTION SECTION:")
            print(finalResponse.question[0])
            print()
            print("ANSWER SECTION:")
            print(finalResponse.answer[0])
            # write successful output to file
            file.write("\nIP: " + str(finalResponse.answer[0][0]) + "\n\n")
            print()
            end = time.time()
            print("Query time: " + str(end-start) + " seconds")
            print("WHEN: " + str(now))
            break
        except:
            continue
    if(not validDomainName):
        # write output to file if given invalid domain name
        file.write("\nOutput: Invalid Domain\n\n")
        print("Invalid Domain")
    file.close()


def dnsResolver(domainName, serverip):
    query = dns.message.make_query(
        str(domainName), rdtype, rdclass)  # create a query
    # gets the response of the query
    response = dns.query.udp(query, str(serverip), timeout)

    # answer is avaliable in the response
    if(response.answer):
        if(response.answer[0].rdtype == 5):  # checks if answer a CNAME
            for nameRootServer in rootServer:
                # gets the IP of the CNAME using recursion
                newip = dnsResolver(
                    str(response.answer[0][0]), nameRootServer).answer[0][0]
                return dnsResolver(domainName, str(newip))
        return response  # returns the response that has the answer
    # answer is not found in the response
    else:
        # additional is missing so have to find the IP of the NS
        if((response.authority) and (not response.additional)):
            for nameServer in response.authority[0]:
                if (nameServer.rdtype == 2):  # checks if authority is a NS
                    for nameRootServer in rootServer:
                        # gets the IP of the NS using recursion
                        newip = dnsResolver(
                            str(nameServer), nameRootServer).answer[0][0]
                        return dnsResolver(domainName, str(newip))
        # addition is present so use the IP in the additional
        elif((response.authority) and (response.additional)):
            for nameServer in response.additional:
                if (nameServer.rdtype == 1):  # checks if additional is rdtype A
                    return dnsResolver(domainName, str(nameServer[0]))


if __name__ == '__main__':
    main()
