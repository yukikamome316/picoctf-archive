def decrypt(a, b, cipher):
  p = 97
  g = 31
  plaintext = ""
  for encrypted_value in cipher:
    char_value = (encrypted_value * pow(a, -1, p)) % p
    plaintext += chr(char_value)
  return plaintext


if __name__ == "__main__":
  a = 94
  b = 29
  cipher = [260307, 491691, 491691, 2487378, 2516301, 0, 1966764, 1879995, 1995687, 1214766, 0, 2400609, 607383, 144615, 1966764, 0, 636306, 2487378, 28923, 1793226, 694152, 780921, 173538, 173538, 491691, 173538, 751998, 1475073, 925536, 1417227, 751998, 202461, 347076, 491691]
  
  print(decrypt(a, b, cipher))
  