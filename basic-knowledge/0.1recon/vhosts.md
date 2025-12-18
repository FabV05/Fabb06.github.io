# Virtual Host



The key difference between VHosts and sub-domains is that a VHost is basically a 'sub-domain' served on the same server and has the same IP, such that a single IP could be serving two or more different websites.

```shell-session
$ curl -s http://192.168.10.10 -H "Host: randomtarget.com"

<html>
    <head>
        <title>Welcome to randomtarget.com!</title>
    </head>
    <body>
        <h1>Success! The randomtarget.com server block is working!</h1>
    </body>
</html>
```


## Gobuster

```
gobuster vhost -u http://domain.htb:8008 -w /usr/share/seclists/Discovery/DNS/namelist.txt --append-domain | grep -v "301"
```

## Ffuf

### Exclude redirect 302

```
ffuf -u http://permx.htb -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt -H "Host: FUZZ.permx.htb" -fs 0 -mc all -fc 302
```

### Filter by size

```shell-session
ffuf -w ./vhosts -u http://192.168.10.10 -H "HOST: FUZZ.randomtarget.com" -fs 612
```

* `-w`: Path to our wordlist
* `-u`: URL we want to fuzz
* `-H "HOST: FUZZ.randomtarget.com"`: This is the `HOST` Header, and the word `FUZZ` will be used as the fuzzing point.
* `-fs 612`: Filter responses with a size of 612, default response size in this case.

