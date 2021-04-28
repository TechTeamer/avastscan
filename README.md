# Avast-Server
avast-server is a utility to scan files through http requests without the files originally being in the same machine.

### Documentation
- ```node .bin/avast-server``` 
You can set the following env variables

- AVAST_SERVER_PORT (default: 4311)
  Wev Server Port
- AVAST_SERVER_REQ_SIZE_LIMIT (default: 50mb) 
  Maximum request size that the web server accepts. 
  NOTE: use the format (size)mb (or kb, etc)
- AVAST_SERVER_MAX_TIMEOUT (default: 30000)
  Time out for requests. (In miliseconds)
- AVAST_SERVER_SOCK_FILE (default: /var/run/avast/scan.sock)
  Socket file for avast
  
### Endpoints

```/scan POST```
##### parameters
```file``` {{ File to scan }}

##### response examples
```json
{
  "is_infected": false,
  "is_excluded": false
}
```

```json
{
  "is_infected": true,
  "malware_name": "malware name"
}
```

---------
 ```/info GET```
 
 ##### response examples
 ````json
{
    "version": "3.0.3",
    "virusDefinitionsVersion": "21040804"
}
````
 
# Avast Client

Avast client needs to be instantiated with an options object as parameter.
```js
{
  baseURL: 'http://my-avast-server-url', // URL of Avast Server
  timeout: 10000 //timewut for requests in MS, default is 30000
}
```
