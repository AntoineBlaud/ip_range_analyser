from faker import Faker

fak = Faker()

out = open('ip.txt', 'w')
for _ in range(100000):
    out.write(fak.ipv4() + '\n')