with open("enc", "r", encoding="utf-8") as f:
  enc = f.read().strip()

for i in range(len(enc)):
  low = (ord(enc[i]) >> 8)
  high = (ord(enc[i]) & 0xFF)
  print(chr(low) + chr(high), end="")
