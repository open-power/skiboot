.. _skiboot-6.6.5:

==============
skiboot-6.6.5
==============

skiboot 6.6.5 was released on Wednesday January 06, 2021. It replaces
:ref:`skiboot-6.6.4` as the current stable release in the 6.6.x series.

It is recommended that v6.6.5 be used instead of v6.6.4 version due to the
bug fixes it contains.

Bug fixes included in this release are:

- SBE: Account cancelled timer request

- SBE: Rate limit timer requests

- SBE: Check timer state before scheduling timer

- xscom: Fix xscom error logging caused due to xscom OPAL call

- xive/p9: Remove assert from xive_eq_for_target()

- core/platform: Fallback to full_reboot if fast-reboot fails
