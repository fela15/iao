from termcolor import colored, cprint 

def parse(data, port, origin, scope='all'):
    if scope == 'all':
        print '[',
        if origin == 'server': cprint(origin, 'green', end='')
        if origin == 'client': cprint(origin, 'yellow', end='')
        print "({})] {}".format( port, data.encode('hex'))
    elif scope == 'server':
        if origin == 'server':
            print '[',
            cprint(origin, 'green', end='')
            print "({})] {}".format( port, data.encode('hex'))
    elif scope == 'client':
        if origin == 'client':
            print '[',
            cprint(origin, 'yellow', end='')
            print "({})] {}".format( port, data.encode('hex'))

