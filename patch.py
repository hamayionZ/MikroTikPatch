name: RouterOS 7.22.1 Universal Patcher
on:
  workflow_dispatch:
    inputs:
      arch:
        description: 'Architecture'
        required: true
        default: 'x86'
        type: choice
        options: [x86, arm64]

jobs:
  Build:
    runs-on: ubuntu-22.04
    env:
      # Inhein GitHub Secrets mein lazmi set karein (64 characters hex)
      CUSTOM_LICENSE_PUBLIC_KEY: ${{ secrets.CUSTOM_LICENSE_PUBLIC_KEY }}
      CUSTOM_LICENSE_PRIVATE_KEY: ${{ secrets.CUSTOM_LICENSE_PRIVATE_KEY }}
      CUSTOM_NPK_SIGN_PUBLIC_KEY: ${{ secrets.CUSTOM_NPK_SIGN_PUBLIC_KEY }}
      CUSTOM_NPK_SIGN_PRIVATE_KEY: ${{ secrets.CUSTOM_NPK_SIGN_PRIVATE_KEY }}
      MIKRO_LICENSE_PUBLIC_KEY: '4a595133644d6736523959326e5535354d6d4a4d6b6e4d50516b32693836374a'
      MIKRO_NPK_SIGN_PUBLIC_KEY: 'c33b9347898862f18390885141e6b3531b402868c78c3c4343166443685e1327'

    steps:
    - name: Checkout
      uses: actions/checkout@v4

    - name: Install Tools
      run: sudo apt-get update && sudo apt-get install -y mkisofs xorriso squashfs-tools mtools wget zip

    - name: Download ROS
      run: |
        V=$(wget -qO- https://download.mikrotik.com/routeros/NEWESTa7.stable | cut -d ' ' -f1)
        echo "VERSION=$V" >> $GITHUB_ENV
        wget -nv -O original.iso https://download.mikrotik.com/routeros/$V/mikrotik-$V.iso
        wget -nv -O pkgs.zip https://download.mikrotik.com/routeros/$V/all_packages-x86-$V.zip
        mkdir -p ./pkgs && unzip pkgs.zip -d ./pkgs

    - name: Patch Kernel (The Loader)
      run: |
        # ISO extract karein
        mkdir -p ./iso_dir
        xorriso -osirrox on -indev original.iso -extract / ./iso_dir
        chmod -R 777 ./iso_dir

        # UEFI Kernel Patch
        mcopy -i ./iso_dir/efiboot.img ::linux.x86_64 ./vmlinux
        sudo -E python3 patch.py kernel ./vmlinux
        mcopy -D o -i ./iso_dir/efiboot.img ./vmlinux ::linux.x86_64

        # Legacy Kernel Patch
        cp ./vmlinux ./iso_dir/isolinux/linux
        echo "Loader Patched."

    - name: Create Option NPK
      run: |
        # Option SFS build
        mkdir -p ./opt/bin
        cp ./busybox/busybox_x86 ./opt/bin/busybox
        cp ./keygen/keygen_x86 ./opt/bin/keygen
        chmod +x ./opt/bin/*
        cd ./opt/bin && for c in $(./busybox --list); do ln -sf busybox $c; done && cd ../..
        mksquashfs opt option.sfs -quiet -comp xz -no-xattrs -b 256k

        # Build & Sign NPK
        TEMPLATE=$(find ./pkgs -name "gps-*.npk" | head -n 1)
        sudo -E python3 npk.py create "$TEMPLATE" ./pkgs/option.npk option ./option.sfs
        
        # Sign all packages
        for f in ./pkgs/*.npk; do
          sudo -E python3 patch.py npk "$f" || true
          sudo -E python3 npk.py sign "$f" "$f"
        done

    - name: Build ISO
      run: |
        cp ./pkgs/*.npk ./iso_dir/
        mkisofs -o patched.iso -V "MikroTik" \
          -b isolinux/isolinux.bin -c isolinux/boot.cat \
          -no-emul-boot -boot-load-size 4 -boot-info-table \
          -eltorito-alt-boot -e efiboot.img -no-emul-boot \
          -R -J ./iso_dir

    - name: Upload
      uses: actions/upload-artifact@v4
      with:
        name: Patched-ISO
        path: patched.iso
