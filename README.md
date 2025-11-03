# CT_RSA

.\.venv\Scripts\Activate.ps1

python et le nom du fichier

pour fetch_ct.py || python fetch_ct.py --count {le nombre que l'on veut}

deactivate

Certificats, web et calculs de clés privées
— Récupérer au moins 1 million de certificats en utilisant Certificate Transparency en écrivant un crawler
et en téléchargeant les certificats de la PKI Certificate Transparancy utilisant les API publiques
documentées [6]. La liste des API pour récupérer les données est décrite par une RFC. [7]
— Trier les clés par taille
— Recherche de doublons (clés identiques)
— Recherche de clés différentes, mais ayant un facteur commun
— Lancer Batch GCD [1] sur les autres clés, il est possible de trouver soit p soit q commun a une clé
sachant que n = pq
— Bacth GCD existe en Python et en C++, ne pas le recoder !
