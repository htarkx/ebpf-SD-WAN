nix --extra-experimental-features 'nix-command flakes' \
  develop . \
  --option max-jobs 1 \
  --option cores 1 \
  --option http-connections 2 \
  --option connect-timeout 10 \
  --option stalled-download-timeout 30
