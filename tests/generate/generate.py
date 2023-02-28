from faker import Faker

fak = Faker()

out = open('ip.txt', 'w')
for _ in range(2000000):
    out.write(fak.ipv4() + '\n')