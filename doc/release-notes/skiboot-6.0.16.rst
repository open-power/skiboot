.. _skiboot-6.0.16:

==============
skiboot-6.0.16
==============

skiboot 6.0.16 was released on Friday February 1st, 2019. It replaces
:ref:`skiboot-6.0.15` as the current stable release in the 6.0.x series.

It is recommended that 6.0.16 be used instead of any previous 6.0.x version
due to the bug fixes it contains.

Bug fixes included in this release are:

- p9dsu: Fix p9dsu default variant

  Add the default when no riser_id is returned from the ipmi query.

  This addresses: https://github.com/open-power/boston-openpower/issues/1369

  Allow a little more time for BMC reply and cleanup some label strings.

- phb4: Generate checkstop on AIB ECC corr/uncorr for DD2.0 parts

  On DD2.0 parts, PCIe ECC protection is not warranted in the response
  data path. Thus, for these parts, we need to flag any ECC errors
  detected from the adjacent AIB RX Data path so the part can be
  replaced.

  This patch configures the FIRs so that we escalate these AIB ECC
  errors to a checkstop so the parts can be replaced.
