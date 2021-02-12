#!/bin/bash
set -o nounset -o pipefail -o errexit

die() {
    echo "$(basename $0): $@" >&2 ; exit 1
}

log_section() {
   printf '=%.0s' {1..72} ; printf "\n"
   printf "=\t%s\n" "" "$@" ""
}

RESULT_DIR=${RESULT_DIR:-result}

DEPLOY_USER=${DEPLOY_USER:-reposync}
DEPLOY_HOST=${DEPLOY_HOST:-pfbuilder.inverse}
DEPLOY_UPDATE=${DEPLOY_UPDATE:-"hostname -f"}

REPO_BASE_DIR=${REPO_BASE_DIR:-/var/www/repos/PacketFence}
PUBLIC_REPO_BASE_DIR=${PUBLIC_REPO_BASE_DIR:-/var/www/inverse.ca/downloads/PacketFence}

DEPLOY_SRPMS=${DEPLOY_SRPMS:-no}
RPM_BASE_DIR=${RPM_BASE_DIR:-"${REPO_BASE_DIR}/RHEL7"}
RPM_DEPLOY_DIR=${RPM_DEPLOY_DIR:-devel/x86_64}
RPM_RESULT_DIR=${RPM_RESULT_DIR:-"${RESULT_DIR}/centos"}

DEB_UPLOAD_DIR=${DEB_UPLOAD_DIR:-/root/debian/UploadQueue}
DEB_DEPLOY_DIR=${DEB_DEPLOY_DIR:-debian-devel}
DEB_RESULT_DIR=${DEB_RESULT_DIR:-"${RESULT_DIR}/debian"}

MAINT_DEPLOY_DIR=${MAINT_DEPLOY_DIR:-tmp}

rpm_deploy() {
    for release_name in $(ls $RPM_RESULT_DIR); do
        src_dir="$RPM_RESULT_DIR/${release_name}"
        dst_repo="$RPM_BASE_DIR/$RPM_DEPLOY_DIR"
        dst_dir="$DEPLOY_USER@$DEPLOY_HOST:$dst_repo"
        declare -p src_dir dst_dir

        if [ "$DEPLOY_SRPMS" == "no" ]; then
            echo "Removing SRPMS according to '$DEPLOY_SRPMS' value"
            rm -v $src_dir/*.src.rpm
        else
            echo "Keeping SRPMS according to '$DEPLOY_SRPMS' value"
        fi

        echo "copy: $src_dir/*.rpm -> $dst_dir/RPMS"
        scp $src_dir/*.rpm $dst_dir/RPMS \
            || die "scp failed"

        dst_cmd="$DEPLOY_USER@$DEPLOY_HOST $DEPLOY_UPDATE"
        echo "running following command: $dst_cmd"
        ssh $dst_cmd \
            || die "update failed"
    done
}

deb_deploy() {
    for release_name in $(ls $DEB_RESULT_DIR); do
        src_dir="$DEB_RESULT_DIR/${release_name}"
        dst_dir="$DEPLOY_USER@$DEPLOY_HOST:$DEB_UPLOAD_DIR"
        changes_file=$(basename $(ls $DEB_RESULT_DIR/${release_name}/*.changes | tail -1))
        declare -p src_dir dst_dir changes_file
        echo "copy: $src_dir/* -> $dst_dir"
        scp $src_dir/* $dst_dir/ \
            || die "scp failed"
        
        dst_cmd="$DEPLOY_USER@$DEPLOY_HOST $DEPLOY_UPDATE"
        extra_args="${release_name} ${changes_file}"
        echo "running following command: $dst_cmd $extra_args"
        ssh $dst_cmd $extra_args \
            || die "update failed"
    done
}

maint_deploy() {
    # warning: slashs at end of dirs are significant for rsync
    src_dir="$RESULT_DIR/"
    dst_repo="$PUBLIC_REPO_BASE_DIR/$MAINT_DEPLOY_DIR/"
    dst_dir="$DEPLOY_USER@$DEPLOY_HOST:$dst_repo"
    declare -p src_dir dst_dir
    echo "rsync: $src_dir -> $dst_dir"
    rsync -avz $src_dir $dst_dir \
        || die "scp failed"
}

packetfence_release_centos7_deploy() {
    src_dir="$RPM_RESULT_DIR/7"
    dst_repo="$PUBLIC_REPO_BASE_DIR/RHEL7"
    dst_dir="$DEPLOY_USER@$DEPLOY_HOST:$dst_repo"
    pf_release_rpm_file=$(basename $(ls $RPM_RESULT_DIR/7/packetfence-release*))
    pkg_dest_name=${PKG_DEST_NAME:-"packetfence-release-7.${CI_COMMIT_REF_SLUG}.noarch.rpm"}
    declare -p src_dir dst_dir pf_release_rpm_file pkg_dest_name

    echo "scp: ${src_dir}/${pf_release_rpm_file} -> ${dst_dir}/${pkg_dest_name}"
    scp "${src_dir}/${pf_release_rpm_file}" "${dst_dir}/${pkg_dest_name}" \
        || die "scp failed"
}

log_section "Display artifacts"
tree ${RESULT_DIR}

log_section "Deploy $1 artifacts"
case $1 in
    rpm) rpm_deploy ;;
    deb) deb_deploy ;;
    maintenance) maint_deploy ;;
    packetfence-release) packetfence_release_centos7_deploy ;;
    *)   die "Wrong argument"
esac
