# CoProxy  
CoProxy is a light weigth http proxy server implement with coroutine.  
### develement status  
the basis functions is ok, no memory leaks now.
no full unit tested.  
### Features  
* dns merge query  
* dns cache  
* tcp connection poll  
* synchronous work flow, easier to understand and custom  
* one thread only,better performance compared with one-thread-per-connection model  

### Plantforms  
Support linux only.  
### third party dependences  
all third party dependences source code has been included in th source code  
* [libevent](https://github.com/nmathewson/Libevent)  
* [coroutine](https://github.com/cloudwu/coroutine)  

### Build  
Just enter the folder & make  
