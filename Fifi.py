from neo4j import GraphDatabase
import datetime
import csv
import argparse

# Inspired by:
# - https://gist.github.com/mgeeky/3ce3b12189a6b7ee3c092df61de6bb47
# - https://github.com/awsmhacks/awsmBloodhoundCustomQueries
# - https://hausec.com/2019/09/09/bloodhound-cypher-cheatsheet/
# - https://github.com/Scoubi/BloodhoundAD-Queries/blob/master/BH%20Red2Blue.txt


class App:

    def __init__(self, uri, user, password):
        self.driver = GraphDatabase.driver(uri, auth=(user, password))

    def close(self):
        self.driver.close()

    def get_number_of_GPOs(self):
        with self.driver.session() as session:
            result = session.read_transaction(self._get_number_of_X, "GPO")
            return result

    def get_number_of_OUs(self):
        with self.driver.session() as session:
            result = session.read_transaction(self._get_number_of_X, "OU")
            return result

    def get_number_of_USERs(self):
        with self.driver.session() as session:
            result = session.read_transaction(self._get_number_of_X, "User")
            return result

    def get_number_of_GROUPs(self):
        with self.driver.session() as session:
            result = session.read_transaction(self._get_number_of_X, "Group")
            return result

    def get_number_of_COMPUTERs(self):
        with self.driver.session() as session:
            result = session.read_transaction(self._get_number_of_X, "Computer")
            return result

    def get_number_of_DOMAINADMINS(self, da, domain):
        with self.driver.session() as session:
            query = f"MATCH(u:User) -[r:MemberOf*1..]->(g:Group {{name:'{da}@{domain}'}}) return COUNT(DISTINCT(u))"
            result = session.read_transaction(self._get_number_of, query)
            return result

    def get_number_of_X_with_path_to_DA(self, source, da, domain, exclude_admincount = False):
        with self.driver.session() as session:
            if exclude_admincount:
                query = f"MATCH shortestPath((u:{source} {{admincount:false}}) -[r*1..]->(g:Group {{name:'{da}@{domain}'}})) return COUNT(DISTINCT(u))"
            else: 
                query = f"MATCH shortestPath((u:{source} ) -[r*1..]->(g:Group {{name:'{da}@{domain}'}})) return COUNT(DISTINCT(u))"
            result = session.read_transaction(self._get_number_of, query)
            return result

    def get_number_of_X_with_dangerours_path_to_DA(self, source, da, domain, exclude_admincount = False):
        with self.driver.session() as session:
            if exclude_admincount:
                query = f"MATCH shortestPath((u:{source} {{admincount:false}}) -[r:MemberOf|HasSession|AdminTo|AllExtendedRights|AddMember|ForceChangePassword|GenericAll|GenericWrite|Owns|WriteDacl|WriteOwner|ExecuteDCOM|AllowedToDelegate|ReadLAPSPassword|Contains|GpLink|AddAllowedToAct|AllowedToAct*1..]->(g:Group {{name:'{da}@{domain}'}})) return COUNT(DISTINCT(u))"
            else: 
                query = f"MATCH shortestPath((u:{source}) -[r:MemberOf|HasSession|AdminTo|AllExtendedRights|AddMember|ForceChangePassword|GenericAll|GenericWrite|Owns|WriteDacl|WriteOwner|ExecuteDCOM|AllowedToDelegate|ReadLAPSPassword|Contains|GpLink|AddAllowedToAct|AllowedToAct*1..]->(g:Group {{name:'{da}@{domain}'}})) return COUNT(DISTINCT(u))"
            result = session.read_transaction(self._get_number_of, query)
            return result

    def get_average_attack_Path_len_of_X_to_DA_dangerous_perms(self, source, da, domain):
            edge = "r:MemberOf|HasSession|AdminTo|AllExtendedRights|AddMember|ForceChangePassword|GenericAll|GenericWrite|Owns|WriteDacl|WriteOwner|ExecuteDCOM|AllowedToDelegate|ReadLAPSPassword|Contains|GpLink|AddAllowedToAct|AllowedToAct*1.."
            return self.get_average_attack_Path_len_of_X_to_DA(source, da, domain, edge)

    def get_average_attack_Path_len_of_X_to_DA(self, source, da, domain, edge = "r*1.."):
        with self.driver.session() as session:
            query = f"MATCH p = shortestPath((n:{source})-[{edge}]->(g:Group {{name:'{da}@{domain}'}})) RETURN toInteger(AVG(LENGTH(p))) as avgPathLength"
            result = session.read_transaction(self._get_number_of, query)
            return result
    
    def get_number_of_KERBEROASTABLE_user(self):
        with self.driver.session() as session:
            query = "MATCH (n:User) WHERE n.hasspn=true RETURN COUNT(DISTINCT(n))"
            result = session.read_transaction(self._get_number_of, query)
            return result
    
    def get_number_of_KERBEROASTABLE_user_with_PW_older_5_years(self):
        with self.driver.session() as session:
            query = "MATCH (u:User) WHERE u.hasspn=true AND u.pwdlastset < (datetime().epochseconds - (1825 * 86400)) AND NOT u.pwdlastset IN [-1.0, 0.0] RETURN  COUNT(DISTINCT(u))"
            result = session.read_transaction(self._get_number_of, query)
            return result
    
    def run_query_write_csv(self, query, outfile):
        with self.driver.session() as session:
            try:
                result = session.read_transaction(self._get, query)
                with open(outfile, 'w', newline='') as f:
                    if len(result) > 0:
                        keys = result[0].keys()
                        w = csv.DictWriter(f, keys)
                        w.writeheader()
                        w.writerows(result)
            except:
                with open(outfile, 'w', newline='') as f:
                    f.write("Query failed\n")
                    f.write(query)

    @staticmethod
    def _get_number_of_X(tx, element):
        result = tx.run(f"Match (n:{element}) return COUNT(n)")
        return result.single()[0]

    @staticmethod
    def _get_number_of(tx, query):
        result = tx.run(f"{query}")
        return result.single()[0]
    
    @staticmethod
    def _get(tx, query):
        return tx.run(query).data()
    
    @staticmethod
    def percentage(part, whole):
        return 100 * float(part)/float(whole)

    @staticmethod
    def get_date(timestamp):
        return datetime.datetime.fromtimestamp(timestamp).strftime('%d-%m-%Y')


if __name__ == "__main__":

    parser = argparse.ArgumentParser(description="Fifi Tool")
    parser.add_argument("-l", "--language", help="Domain language", choices=['en', 'de'], required=True)
    parser.add_argument("-p", "--password", help="Neo4j password", required=True)
    parser.add_argument("-u", "--username", help="Neo4j username", required=True)
    parser.add_argument("-d", "--domain", help="Name of Domain", required=True)
    parser.add_argument("--host", help="Neo4j host", default="localhost")
    parser.add_argument("--port", help="Neo4j port", default="7687")
    
    args = parser.parse_args()
    config = vars(args)

    if config['language'] == "en":
        english_domain = True
    else:
        english_domain = False
    
    domain = config["domain"].upper()

    eng_dict = {
        "DA": "DOMAIN ADMINS",
        "DC": "DOMAIN-CONTROLLERS",
        "DU": "DOMAIN USER"
        }

    de_dict = {
        "DA": "DOMÄNEN-ADMINS",
        "DC": "DOMÄNENCONTROLLER",
        "DU": "DOMÄNEN-BENUTZER"
        }

    used_dict = 0
    if english_domain:
        used_dict = eng_dict
    else:
        used_dict = de_dict

    da = used_dict["DA"]
    du = used_dict["DU"]
    dc = used_dict["DC"]

    neo4jconnection = "bolt://" + config["host"] + ":" + config["port"]
    MyApp = App(neo4jconnection, config["username"], config["password"])

    queries = [
        ("Get All Domain Admins", f"MATCH (c:User)-[:MemberOf*1..]->(g:Group{{name: '{da}@{domain}'}}) return DISTINCT(c.name) as DomAdms", "DomainAdmins.csv"),
        ("Get all Domain Admins not logged on to a DC", f"MATCH (c:Computer)-[:MemberOf]->(t:Group) WHERE t.name = '{dc}@{domain}' WITH COLLECT(c.name) as DC MATCH p=(c:Computer)-[:HasSession]->(n:User)-[:MemberOf*1..]->(g:Group {{name:'{da}@{domain}'}}) where NOT c.name IN DC RETURN DISTINCT(n.name) as Username, (c.name) as NonDC", "DomainadminsOnNoneDC.csv"),
        ("Get User with most admin rights", f"MATCH shortestPath((u:User)-[:MemberOf|AdminTo*1..]->(c:Computer)) RETURN u.name AS USER, count(DISTINCT(c.name)) AS COMPUTER ORDER BY count(DISTINCT(c.name)) DESC", "UserWithMostLocalAdminsRights.csv"),
        ("Get Computer with most lokal admins", f"MATCH shortestPath((n:User)-[r:MemberOf|AdminTo*1..]->(m:Computer)) RETURN DISTINCT(m.name) as Computer, COUNT(DISTINCT(n)) as NumAdmins ORDER BY NumAdmins desc", "ComputerWithMostAdmins.csv"),
        ("Get User with userpassword set",f"MATCH (u:User) WHERE NOT u.userpassword IS null RETURN u.name as Username,u.userpassword as Userpassword","UserWithPassword.csv"),
        ("Get all computer (ex DC) with unconstrained dellegation", f"MATCH (c1:Computer)-[:MemberOf*1..]->(g:Group{{name:'{dc}@{domain}'}}) WITH COLLECT(c1.name) AS domainControllers MATCH (c2:Computer {{unconstraineddelegation:true}}) WHERE NOT c2.name IN domainControllers RETURN c2.name as Computer ORDER BY c2.name ASC", "UnconstrainedDelegation.csv"),
        ("Get all computer with 'passw' in describtion.", f"MATCH (u:User) WHERE u.description =~ '(?i).*pass.*' RETURN u.name as Username, u.description as Description", "UserWithPassInDescription.csv"),
        ("Users with interessting perms agains GPOs", f"MATCH shortestPath((u:User{{admincount:False}})-[r:MemberOf|AllExtendedRights|GenericAll|GenericWrite|Owns|WriteDacl|WriteOwner|GpLink*1..]->(g:GPO)) RETURN DISTINCT(u.name) as Username, COUNT(DISTINCT(g)) as NumGPOs", "UserWithInterestingRightsAgainstGPOs.csv"),
        ("Computer with Admin rights to other computer", f"MATCH (c1:Computer) OPTIONAL MATCH (c1)-[:AdminTo]->(c2:Computer) OPTIONAL MATCH (c1)-[:MemberOf*1..]->(:Group)-[:AdminTo]->(c3:Computer) WITH COLLECT(c2) + COLLECT(c3) AS tempVar,c1 UNWIND tempVar AS computers RETURN c1.name AS COMPUTER,COUNT(DISTINCT(computers)) AS ADMIN_TO_COMPUTERS ORDER BY COUNT(DISTINCT(computers)) DESC", "ComputerWithLocalAdminRightsToOthers.csv"),
        ("Computers where \"Domain User\" are admin", f"MATCH p=(m:Group{{name: '{du}@{domain}'}})-[r:AdminTo]->(n:Computer) RETURN DISTINCT(n.name) As Computer", "ComputerWithDomainUserAsLocalAdmins.csv"),
        ("Kerberoastable Users, who has not changed their Password in the last 5 years", f"MATCH (u:User) WHERE u.hasspn=true AND u.pwdlastset < (datetime().epochseconds - (1825 * 86400)) AND NOT u.pwdlastset IN [-1.0, 0.0] RETURN u.name as Username, u.pwdlastset as PasswdLastSet order by u.pwdlastset","KerberoastableUserWithOldPWs.csv"),
        ("ASREPRoastable Users, who has not changed their Password in the last 5 years", f"MATCH (u:User) WHERE u.dontreqpreauth=true AND u.pwdlastset < (datetime().epochseconds - (1825 * 86400)) AND NOT u.pwdlastset IN [-1.0, 0.0] RETURN u.name as Username, u.pwdlastset as PasswdLastSet order by u.pwdlastset","ASRepRoastableUserWithOldPWs.csv"),
        ("Users, who has not changed their Password in the last 3 years", f"MATCH (u:User) WHERE u.pwdlastset < (datetime().epochseconds - (1095 * 86400)) AND NOT u.pwdlastset IN [-1.0, 0.0] RETURN u.name as Username, u.pwdlastset as PasswdLastSet order by u.pwdlastset","PasswordsOlderThreeYears.csv"),
        ("Users with High Value Targets", f"MATCH (m:User),(n {{highvalue:true}}),p=shortestPath((m)-[r:MemberOf|HasSession|AdminTo|AllExtendedRights|AddMember|ForceChangePassword|GenericAll|GenericWrite|Owns|WriteDacl|WriteOwner|ExecuteDCOM|AllowedToDelegate|ReadLAPSPassword|Contains|GpLink|AddAllowedToAct|AllowedToAct*1..]->(n)) WHERE NONE (r IN relationships(p) WHERE type(r)= 'GetChanges') AND NONE (r in relationships(p) WHERE type(r)='GetChangesAll') AND NOT m=n RETURN m.name as Username, COUNT(DISTINCT(n.name)) as NumHighVal order by NumHighVal desc", "UserCanReachHighValueTargets.csv"),
        ("Nodes can perform DCsync (ex DC)", f"MATCH (c:Computer)-[:MemberOf*1..]->(g:Group{{name:'{dc}@{domain}'}}) with collect(c) as DCs MATCH (n1)-[:MemberOf|GetChanges*1..]->(u:Domain {{name: '{domain}'}}) where not n1 in DCs WITH n1,u MATCH (n1)-[:MemberOf|GetChangesAll*1..]->(u) WITH n1,u MATCH (n1)-[:MemberOf|GetChanges|GetChangesAll*1..]->(u) RETURN DISTINCT(n1.name) as NodeName", "NodesCanDCSync.csv"),
        ("High Value Group with their members", "MATCH (g:Group {highvalue:TRUE})<-[:MemberOf*1..]-(u:User) return g.name as Group, COUNT(DISTINCT(u.name)) as NumUsers ORDER BY COUNT(DISTINCT(u.name)) DESC", "HighValueGroupsWithNumber.csv"),
        ("Computer with high value user logged on", f"MATCH (c:Computer)-[:HasSession]->(u:User)-[:MemberOf*1..]->(g:Group {{domain:'{domain}',highvalue:true}}) RETURN DISTINCT(c.name) as ComputerWithHighValSession ORDER BY c.name ASC", "ComputerWithHighValueSession.csv"),
        ("Objects Controlled by Everyone",f"MATCH (g:Group {{domain:'{domain}'}}) WHERE g.objectid CONTAINS 'S-1-1-0' OPTIONAL MATCH (g)-[{{isacl:true}}]->(n) OPTIONAL MATCH (g)-[:MemberOf*1..]->(:Group)-[{{isacl:true}}]->(m) WITH COLLECT(n) + COLLECT(m) as tempVar UNWIND tempVar AS objects RETURN DISTINCT(objects) ORDER BY objects.name ASC","ObjectsControlledByEveryone.csv"),
        ("Objects Controlled by Authenticated Users", f"MATCH (g:Group {{domain:'{domain}'}}) WHERE g.objectid CONTAINS 'S-1-5-11' OPTIONAL MATCH (g)-[{{isacl:true}}]->(n) OPTIONAL MATCH (g)-[:MemberOf*1..]->(:Group)-[{{isacl:true}}]->(m) WITH COLLECT(n) + COLLECT(m) as tempVar UNWIND tempVar AS objects RETURN DISTINCT(objects) ORDER BY objects.name ASC", "ObjectsControlledByAuthenticatedUsers.csv"),
        ("Objects Controlled by Domain Users", f"MATCH (g:Group {{domain:'{domain}'}}) WHERE g.objectid ENDS WITH '-513' OPTIONAL MATCH (g)-[{{isacl:true}}]->(n) OPTIONAL MATCH (g)-[:MemberOf*1..]->(:Group)-[{{isacl:true}}]->(m) WITH COLLECT(n) + COLLECT(m) as tempVar UNWIND tempVar AS objects RETURN DISTINCT(objects) ORDER BY objects.name ASC","ObjectsControlledByDomainUsers.csv"),
        ("Find which domain Groups are Admins to what computers", f"MATCH (g:Group) OPTIONAL MATCH (g)-[:AdminTo]->(c1:Computer {{domain:'{domain}'}}) OPTIONAL MATCH (g)-[:MemberOf*1..]->(:Group)-[:AdminTo]->(c2:Computer {{domain:'{domain}'}}) WITH g, COLLECT(c1) + COLLECT(c2) AS tempVar UNWIND tempVar AS computers RETURN g.name as Group,g.highvalue as IsHighValueGroup, computers.name as ComputerName, computers.highvalue as IsHighValueComputer", "GroupsAdminToComputers.csv"),
        ("Number of users who can read LAPS password for each computer", f"MATCH (u:User)-[:MemberOf*0..]->(Group)-[:AllExtendedRights|ReadLAPSPassword]->(c:Computer {{domain:'{domain}'}}) WITH c.name as Computer, COUNT(DISTINCT(u)) as nb_users WHERE nb_users>0 RETURN Computer, nb_users as NumUsers ORDER BY nb_users DESC","UsersCanReadLapsPerComputer.csv"),
        ("Users enabeld but never logged on", f"MATCH (n:User) WHERE n.lastlogontimestamp=-1.0 AND n.enabled=TRUE RETURN DISTINCT(n.name) as Username ORDER BY n.name", "UserNeverLoggedOn.csv"),
        ("Users where Password never expires", "MATCH(u:User{pwdneverexpires:TRUE}) return DISTINCT(u.name) as Username", "UserPWDNeverExpires.csv"),
        ("Users where Password never expires and has an SPN", "MATCH(u:User{pwdneverexpires:TRUE, hasspn:TRUE}) return DISTINCT(u.name) as Username, u.serviceprincipalnames as SPNs", "UserPWDNeverExpiresAndSPN.csv"),
        ("Lowprivilege groups which can change GPOs", f"MATCH(g:Group) where g.name in ['AUTHENTICATED USERS@{domain}', 'EVERYONE@{domain}', '{du}@{domain}'] with g MATCH p=shortestPath((g)-[r:WriteDacl|WriteOwner|GenericWrite]->(gpo:GPO)) return g.name as Group, gpo.name as GPO", "GroupsCanWriteGPOs.csv"),
        ]


    num_gpos = MyApp.get_number_of_GPOs()
    num_ous = MyApp.get_number_of_OUs()
    num_users = MyApp.get_number_of_USERs()
    num_computer = MyApp.get_number_of_COMPUTERs()
    num_groups = MyApp.get_number_of_GROUPs()
    num_dom_admins = MyApp.get_number_of_DOMAINADMINS(used_dict["DA"], domain)
    num_user_to_da = MyApp.get_number_of_X_with_path_to_DA("User", used_dict["DA"], domain)
    num_computer_to_da = MyApp.get_number_of_X_with_path_to_DA("Computer", used_dict["DA"], domain)
    num_user_to_da_dangerours = MyApp.get_number_of_X_with_dangerours_path_to_DA("User", used_dict["DA"], domain)
    num_computer_to_da_dangerous = MyApp.get_number_of_X_with_dangerours_path_to_DA("Computer", used_dict["DA"], domain)
    num_kerberoastable_user = MyApp.get_number_of_KERBEROASTABLE_user()
    num_kerberoastable_user_with_old_pw = MyApp.get_number_of_KERBEROASTABLE_user_with_PW_older_5_years()
    num_average_attackpath_user = MyApp.get_average_attack_Path_len_of_X_to_DA("User", used_dict['DA'], domain)
    num_average_attackpath_computer = MyApp.get_average_attack_Path_len_of_X_to_DA("Computer", used_dict['DA'], domain)
    num_average_attackpath_dangerous_perms_user = MyApp.get_average_attack_Path_len_of_X_to_DA_dangerous_perms("User", used_dict['DA'], domain)
    num_average_attackpath_dangerous_perms_computer = MyApp.get_average_attack_Path_len_of_X_to_DA_dangerous_perms("Computer", used_dict['DA'], domain)


    print("=========Statistics=========")
    print()
    print("Number of GPOS: " + str(num_gpos))
    print("Number of OUs: " + str(num_ous))
    print("Number of Groups: " + str(num_groups))
    print("Number of Users: " + str(num_users))
    print("Number of Computers: " + str(num_computer))
    print("Number of Domain Admins: " + str(num_dom_admins))
    print()
    print("{} ({:3.2f}%) Users who are Domain Admins ".format(num_dom_admins, MyApp.percentage(num_dom_admins, num_users)))
    print("{} ({:3.2f}%) Users who are haveing an potential attack Path do Domain Admins ".format(num_user_to_da_dangerours, MyApp.percentage(num_user_to_da_dangerours, num_users)))
    print("{} ({:3.2f}%) Computers who are haveing an potential attack Path do Domain Admins ".format(num_computer_to_da_dangerous, MyApp.percentage(num_computer_to_da_dangerous, num_users)))
    print()
    print ("The average Attack Path Length from an user is: {}".format(num_average_attackpath_dangerous_perms_user))
    print ("The average Attack Path Length from a Computer is: {}".format(num_average_attackpath_dangerous_perms_computer))
    print()
    print()
    print("=========Infos=========")

    for desc, query, outfile in queries:
        print()
        print("Running query: " + desc + " and writing to: " + outfile)
        print(query)
        MyApp.run_query_write_csv(query, outfile)
    
 
    MyApp.close()