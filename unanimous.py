import sys
from mpyc.runtime import mpc

m = len(mpc.parties)

if m%2 == 0:
    print("Odd number of parties required")
    sys.exit()

t = m//2

voters = list(range(t+1))

if mpc.pid in voters:
    vote = int(sys.argv[1]) if sys.argv[1:] else 1
else:
    vote = None

secbit = mpc.SecFld(2) # secure bits over GF(2)

mpc.run(mpc.start())
votes = mpc.input(secbit(vote), senders = voters)
result = mpc.run(mpc.output(mpc.all(votes), receivers=voters))
mpc.run(mpc.shutdown())

if result is None:
    print("Thanks for serving as oblivious matchmaker;")
elif result:
    print(f"Match: unanimous agreement between {t+1} part{'ies' if t else 'y'}!")
else:
    print(f"No Match: someone disagrees among {t + 1} part{'ies' if t else 'y'}!")