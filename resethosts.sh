resethosts() {
    sudo sed -i '/127.0.0.1 translate-service.scratch.mit.edu/d' /etc/hosts
}

echo "Reset to default behaviour of translate? (requires restart)"
select yn in "Yes" "No"; do
    case $yn in
        Yes ) resethosts; break;;
        No ) exit;;
    esac
done