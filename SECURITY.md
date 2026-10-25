# Security

SweepSafe never handles private keys or seed phrases and never signs anything. Revoke
transactions are built unsigned and signed in your own wallet.

Report vulnerabilities privately through GitHub's "Report a vulnerability" button
(Security tab). Please do not open public issues for exploitable bugs.

Areas of particular interest: anything that could make the viewer or CLI send a
transaction the user did not intend, rendering of hostile token metadata, and
risk-rule disagreements between Python and JavaScript.
