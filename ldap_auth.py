import argparse
from ldap3 import Server, Connection, ALL
from ldap3.core.exceptions import LDAPBindError, LDAPException
import re


class LDAPAuthenticator:

    def __init__(self, ldap_server: str):
        self.ldap_server = ldap_server
        self.ldap_base_dn = self.get_base_dn()

    def extract_org_and_domain(self):
        pattern = r"ldap://([^/]+)"
        match = re.search(pattern, self.ldap_server)
        if match:
            domain_parts = match.group(1).split('.')
            if len(domain_parts) >= 2:
                org = domain_parts[-1]
                domain = domain_parts[-2]
                return org, domain
        return None, None

    def get_base_dn(self):
        server = Server(self.ldap_server, get_info=ALL)
        try:
            conn = Connection(server)
            conn.open()
            conn.start_tls()
            conn.bind()
            # print("Root DSE attributes:", conn.server.info.other)
            # Attempt to get base DN from namingContexts or other attributes
            if 'namingContexts' in conn.server.info.other:
                base_dn = conn.server.info.other['namingContexts'][0]
            elif 'defaultNamingContext' in conn.server.info.other:
                base_dn = conn.server.info.other['defaultNamingContext'][0]
            elif 'rootDomainNamingContext' in conn.server.info.other:
                base_dn = conn.server.info.other['rootDomainNamingContext'][0]
            else:
                raise LDAPException("Unable to determine base DN from Root DSE.")
            conn.unbind()
            # print(base_dn)
            return base_dn
        except Exception as e:
            print(f"An error occurred while fetching the base DN: {e}")
            org, domain = self.extract_org_and_domain()
            if org and domain:
                return f"dc={domain},dc={org}"
            return None

    @staticmethod
    def construct_user_dn(email: str, base_dn: str, organization: str = ''):
        # Extract the user part of the email
        user = email.split('@')[0]
        if organization:
            return f'uid={user},ou=Users,o={organization},{base_dn}'
        else:
            return f'uid={user},ou=Users,{base_dn}'

    def check_login(self, email: str, password: str, organization: str = ''):
        if not self.ldap_base_dn:
            print("Failed to determine the base DN.")
            return False

        user_dn = self.construct_user_dn(email, self.ldap_base_dn, organization)

        try:
            server = Server(self.ldap_server, get_info=ALL)
            conn = Connection(server, user=user_dn, password=password)
            conn.open()
            conn.start_tls()
            conn.bind()
            if conn.bound:
                print("Successfully authenticated to the LDAP Server")
                conn.unbind()
                return True
            else:
                print("Failed to authenticate to the LDAP Server")
                return False
        except LDAPBindError:
            print("Invalid credentails")
            return False
        except Exception as e:
            print(f"An error occurred while connecting to LDAP server: {e}")
            return False


def main():
    parser = argparse.ArgumentParser(description="Check LDAP login credentials.")
    parser.add_argument("-l", "--ldap-server", required=True, help="LDAP server address")
    parser.add_argument("-e", "--email", required=True, help="User email to authenticate")
    parser.add_argument("-p", "--password", required=True, help="User password to authenticate")
    parser.add_argument("-o", "--organization", required=False, help="User organization to authenticate")

    args = parser.parse_args()

    authenticator = LDAPAuthenticator(ldap_server=args.ldap_server)

    if authenticator.check_login(args.email, args.password, args.organization):
        print("Login successful.")
    else:
        print("Login failed.")


if __name__ == "__main__":
    main()
