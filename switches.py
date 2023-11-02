#this section to configure port security
switches = [
    {
        'ip': '192.168.1.1',
        'choice1': 'shut',
        'interface': 'GigabitEthernet0/1',
        'stickyLearning': '0011.2233.4455',
        'max': 10,
        'Mac': '0022.3344.5566',
        'username': 'username1',
        'password': 'password1'
    },
    {
        'ip': '192.168.1.2',
        'choice1': 'restrict',
        'interface': 'FastEthernet0/1',
        'stickyLearning': '0011.2233.4456',
        'max': 15,
        'Mac': '0022.3344.5567',
        'username': 'username2',
        'password': 'password2'
    },
    # Add more switches with their respective parameters
]
