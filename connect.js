{
  onEnter: function (log, args, state) {
    log('connect()');
    log('[+] args[0]> ' + args[0]);
    log('[+] args[1]> ' + args[1]);
    log('[+] args[2]> ' + args[2]);

    this.replace = Memory.alloc(16)

    var a = Memory.readByteArray(args[1], args[2].toInt32());
    var b = new Uint8Array(a);

    this.first = b[4]
    this.second = b[5]
    this.third = b[6]
    this.fourth = b[7]
    this.port = b[2] << 8 | b[3]
    log('[*] Connecting to: ' + this.first + '.' + this.second + '.' + this.third + '.' + this.fourth + ':' + this.port)

    if(b[2] + b[3] == 0xFD) { //replace the netaddr structure with our own, pointint to our vmware interface ip
        this.replace.writeByteArray([0x02, 0x00 ,0x1e ,0xdf ,0xac ,0x10 ,0x6f ,0x01 ,0x00 ,0x00 ,0x00 ,0x00 ,0x00 ,0x00 ,0x00 ,0x00]) //write our own netaddr structure to memory, changing the ip addr
        log('[*] Replacing with our own ipaddress')
        args[1] = this.replace
    } 

  },

  onLeave: function (log, retval, state) {
  }
}
