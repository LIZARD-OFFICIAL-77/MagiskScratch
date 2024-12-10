echo "Preparing for install"

sudo rm -rf .venv > /dev/null 2>&1
sudo rm -rf certgen
sudo rm -rf cert > /dev/null 2>&1

mkdir cert

python -m venv .venv > /dev/null 2>&1

echo "Installing packages... [0/3]"

sudo .venv/bin/python -m ensurepip --default-pip > /dev/null 2>&1

sudo .venv/bin/pip install flask > /dev/null 2>&1

echo "Installing packages... [1/3]"

sudo .venv/bin/pip install git+https://github.com/ultrafunkamsterdam/googletranslate > /dev/null 2>&1

echo "Installing packages... [2/3]"

sudo .venv/bin/pip install requests > /dev/null 2>&1

echo "Installed packages [3/3]"

echo "Fetching DenisMedeiros/certgen for certificate generation..."

git clone https://github.com/DenisMedeiros/certgen.git certgen > /dev/null 2>&1
mv ./certgen/src/certgen/certgen.py ./certgen.py > /dev/null 2>&1
sudo rm -rf certgen > /dev/null 2>&1

echo "Generating authkey..."

tr -dc A-Za-z0-9 < /dev/urandom | head -c 55 > authkey

echo "Generating certificate to mock google translate..."

python certgen.py create --subject-alt-names translate-service.scratch.mit.edu 127.0.0.1  --output-dir ./cert > /dev/null 2>&1

setup_hosts () {
    sudo sh -c "echo '127.0.0.1 translate-service.scratch.mit.edu' >> /etc/hosts"
}

echo "Hijack translate? (requires restart)"
select yn in "Yes" "No"; do
    case $yn in
        Yes ) setup_hosts; break;;
        No ) exit;;
    esac
done

echo "Setup finished!"

echo 'Install certgen-ca.crt to your browser, then execute "bash run.sh in your terminal to run the scratchmagisk server."'

echo 'To access magisk, projects will need your authkey. Simply copy it from the authkey file.'
