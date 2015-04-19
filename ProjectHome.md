**IMPORTANT: Due to constant lack of time, I (Andrei Costin) cannot support/maintain this project. If there is any volunteer to maintain/develop, please contact me or leave a message on libnfc's forum.**

**M**_FCUK_ - `MiFare Classic Universal toolKit`

<img src='http://mfcuk.googlecode.com/files/MFCUK_logo_small.png'>

<a href='https://www.paypal.com/cgi-bin/webscr?cmd=_donations&business=zveriu%40gmail%2ecom&lc=CY&item_name=zveriu%20%2d%20security%26FOSS%20dev%26reasearch&item_number=MFCUK&currency_code=EUR&bn=PP%2dDonationsBF%3abtn_donateCC_LG%2egif%3aNonHosted'><img src='https://www.paypal.com/en_US/i/btn/btn_donateCC_LG.gif' /></a>

Toolkit containing samples and various tools based on and around libnfc and crapto1, with emphasis on Mifare Classic NXP/Philips RFID cards.<br>
<br>
Special emphasis of the toolkit is on the following:<br>
<ul><li>mifare classic weakness demonstration/exploitation<br>
</li><li>demonstrate use of libnfc (and ACR122 readers)<br>
</li><li>demonstrate use of Crapto1 implementation to confirm internal workings and to verify theoretical/practical weaknesses/attacks</li></ul>

<hr />
<b>Wishlist for next version:</b>
<ul><li><del>integrate with mifarecrack (proxmark3 sniffed-logs parser-decrypter) (short-term)</del>
</li><li>write proper proxmark3 parser (c for internal calls and py for external calls)<br>
</li><li>integrate with MFOC (medium-term)<br>
</li><li>integrate with crapto1 3.2<br>
</li><li><del>create initial fingerprint design&implementation. card fingerprinting based on: known plain-text in specific blocks, range of UIDs, etc. (short-term)</del>
</li><li>more templates to add (short-term)<br>
</li><li>summarize decoding info and implement custom decoders (short-medium-term)<br>
</li><li>implement "wiser" template data-structure and appropriate binary data similarity algotihms (medium-term)<br>
</li><li>have command-line (silent+interactive) and GUI (QT-based?) (long-term)</li></ul>

More of research type long-term activity (any volunteers :)?):<br>
<ul><li>go deeper into how UID/block/keys/Nt/Nr relate so that we choose Nt and Nr with shortest crack time (long-term)<br>
</li><li>research on how to shorten time in case prefix of the keys or any part of the keys are known<br>
</li><li>many cards from same issuer might have known plaintext in specific blocks - can this be exploited to speed-up first key recovery and then use optimized darkside/nested to get whole card (medium-term)</li></ul>

<hr />

<b>PACKAGE HISTORY</b>:<br>
<ul><li>zv_mf_dark_side-v0.3.zip    Nov 28      829  KB    604 Downloads<br>
</li><li>zv_mf_dark_side-v0.2.zip    Nov 15      43.2 KB     82 Downloads<br>
</li><li>zv_mf_dark_side-v0.1.zip    Nov 13      40.1 KB     48 Downloads</li></ul>

<hr />

<b>IMPORTANT NOTICE</b> - would greatly appreciate if someone can donate (even used, smashed, but still programmable) things below:<br>
<ul><li>either Nokia 6131 either Nokia 6212<br>
</li><li>iCarte for iPhone</li></ul>

These things are aimed to research, implement the 100% software emulation of Mifare Classic Cards (including UID) and release it open-source under GPL.<br>
<br>
<b>Please contact zveriu</b> through my zveriu's blog regarding donations.<br>
<hr />

<b>DISCLAIMER</b> - The information and reference implementation source/binary contained herein is provided:<br>
<br>
<ul><li>for informational use only as part of academic or research study, especially in the field of informational security, cryptography and secure systems<br>
</li><li>as-is without any warranty, support or liability - any damages or consequences obtained as a result of consulting this information if purely on the side of the reader<br>
</li><li>NOT to be used in illegal circumstances (for example to abuse, hack or trick a system which the reader does not have specific authorizations to such as ticketing systems, building access systems or whatsoever systems using Mifare Classic as core technology)</li></ul>


<h1>Contacts</h1>

<h2>Andrei</h2>

Andrei Costin - <a href='mailto:zveriu@gmail.com'>mailto:zveriu@gmail.com</a>

<a href='http://andreicostin.com'>http://andreicostin.com</a>

<a href='http://code.google.com/p/mfcuk/'>http://code.google.com/p/mfcuk/</a>

<h2>Nethemba Team</h2>

<a href='mailto:mifare@nethemba.com'>mailto:mifare@nethemba.com</a>

Pavol Luptak - <a href='mailto:pavol.luptak@nethemba.com'>mailto:pavol.luptak@nethemba.com</a>

Norbert Szetei - <a href='mailto:norbert.szetei@nethemba.com'>mailto:norbert.szetei@nethemba.com</a>

<a href='http://nethemba.com'>http://nethemba.com</a>

<h1>Papers</h1>

<a href='http://eprint.iacr.org/2009/137.pdf'>http://eprint.iacr.org/2009/137.pdf</a>

<a href='http://www.cs.ru.nl/~petervr/web/papers/grvw_2009_pickpocket.pdf'>http://www.cs.ru.nl/~petervr/web/papers/grvw_2009_pickpocket.pdf</a>

<h1>Links</h1>

<a href='http://www.mikeycard.org'>http://www.mikeycard.org</a>

<a href='http://www.libnfc.org'>http://www.libnfc.org</a> forum<br>
<br>
<a href='http://www.proxmark.org'>http://www.proxmark.org</a> forum