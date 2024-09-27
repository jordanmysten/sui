/// Module: UpgradeErrors

#[allow(unused_field)]
module upgrades::upgrades {
    fun call_friend() {
        upgrades::upgrades_friend::friend_to_be_dropped();
    }
}

module upgrades::upgrades_friend {
    public(package) fun friend_to_be_dropped() {}
}