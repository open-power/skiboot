#include <device.h>
#include <cpu.h>
#include <vpd.h>
#include <interrupts.h>
#include <ccan/str/str.h>
#include <chip.h>

#include "spira.h"
#include "hdata.h"

struct i2c_dev {
	uint8_t i2cm_engine;
	uint8_t i2cm_port;
	__be16 i2c_bus_freq;

	/* i2c slave info */
	uint8_t type;
	uint8_t i2c_addr;
	uint8_t i2c_port;
	uint8_t __reserved;

	__be32 purpose;
	__be32 i2c_link;
	__be16 slca_index;
};

#define P9_I2CM_XSCOM_SIZE 0x1000
#define P9_I2CM_XSCOM_BASE 0xa0000

static struct dt_node *get_i2cm_node(struct dt_node *xscom, int engine)
{
	uint64_t xscom_base = P9_I2CM_XSCOM_BASE + P9_I2CM_XSCOM_SIZE * (uint64_t)engine;
	struct dt_node *i2cm;
	uint64_t freq, clock;

	i2cm = dt_find_by_name_addr(xscom, "i2cm", xscom_base);
	if (!i2cm) {
		i2cm = dt_new_addr(xscom, "i2cm", xscom_base);
		dt_add_property_cells(i2cm, "reg", xscom_base,
			P9_I2CM_XSCOM_SIZE);

		dt_add_property_strings(i2cm, "compatible",
			"ibm,power8-i2cm", "ibm,power9-i2cm");

		dt_add_property_cells(i2cm, "#size-cells", 0);
		dt_add_property_cells(i2cm, "#address-cells", 1);
		dt_add_property_cells(i2cm, "chip-engine#", engine);

		freq = dt_prop_get_u64_def(xscom, "bus-frequency", 0);
		clock = (u32)(freq / 4);
		if (clock)
			dt_add_property_cells(i2cm, "clock-frequency", clock);
		else
			dt_add_property_cells(i2cm, "clock-frequency", 150000000);
	}

	return i2cm;
}

static struct dt_node *get_bus_node(struct dt_node *i2cm, int port, int freq)
{
	struct dt_node *bus;

	bus = dt_find_by_name_addr(i2cm, "i2c-bus", port);
	if (!bus) {
		bus = dt_new_addr(i2cm, "i2c-bus", port);
		dt_add_property_cells(bus, "reg", port);
		dt_add_property_cells(bus, "#size-cells", 0);
		dt_add_property_cells(bus, "#address-cells", 1);

		/* The P9 I2C master is fully compatible with the P8 one */
		dt_add_property_strings(bus, "compatible", "ibm,opal-i2c",
			"ibm,power8-i2c-port", "ibm,power9-i2c-port");

		/*
		 * use the clock frequency as the bus frequency until we
		 * have actual devices on the bus. Adding a device will
		 * reduce the frequency to something that all devices
		 * can tolerate.
		 */
		dt_add_property_cells(bus, "bus-frequency", freq * 1000);
	}

	return bus;
}

struct hdat_i2c_type {
	uint32_t id;
	const char *name;
	const char *compat;
};

static struct hdat_i2c_type hdat_i2c_devs[] = {
	{ 0x1, "gpio", "nxp,pca9551" },
	/* XXX: Please verify that all VPD EEPROMs are of this type */
	{ 0x2, "eeprom", "atmel,24c128" },
	{ 0x3, "tpm", "nuvoton,npct650" },
	{ 0x4, "i2c", NULL },   /* MEX-FPGA */
	{ 0x5, "i2c", NULL },   /* UCX90xx devs for PCI Hotplug */
	{ 0x6, "gpio", "nxp,pca9552" },
	{ 0x7, "gpio", "nxp,pca9553" },
	{ 0x8, "gpio", "nxp,pca9554" },
	{ 0x9, "gpio", "nxp,pca9555" },
	{ 0xa, "i2c", NULL },   /* SMP/OpenCAPI Cable */
	{ 0xb, "eeprom", "atmel,24c256" },
	{ 0xc, "i2c", NULL },   /* Thermal Sensor */
	{ 0xd, "eeprom", "atmel,24c04" },
	{ 0xe, "eeprom", "atmel,24c512" },
	{ 0xf, "eeprom", "atmel,24c32" },
	{ 0x10, "eeprom", "atmel,24c64" },
	{ 0x11, "eeprom", "atmel,24c16" },
	{ 0x12, "i2c", NULL },   /* NVDIA GPU */
	{ 0x13, "i2c", "nxp,lpc11u35" },
};

struct hdat_i2c_label {
	uint32_t id;
	const char *label;
};

static struct hdat_i2c_label hdat_i2c_labels[] = {
	{ 0x1, "led-controller" },
	{ 0x2, "eeprom-pgood" },
	{ 0x3, "eeprom-control" },
	{ 0x4, "tpm" },
	{ 0x5, "module-vpd" },
	{ 0x6, "dimm SPD" },
	{ 0x7, "proc-vpd" },
	{ 0x8, "sbe-eeprom" },
	{ 0x9, "planar-vpd" },
	{ 0xa, "opencapi-topology" },
	{ 0xb, "opencapi-micro-reset" },
	{ 0xc, "nvlink-cable" },
	{ 0xd, "secure-window-open" },
	{ 0xe, "physical-presence" },
	{ 0xf, "mex-fpga" },
	{ 0x10, "thermal-sensor" },
	{ 0x11, "host-i2c-enable" },
	{ 0x12, "gpu-config" },
};

/*
 * this is pretty half-assed, to generate the labels properly we need to look
 * up associated SLCA index and determine what kind of module the device is on
 * and why
 */
static struct hdat_i2c_type *map_type(uint32_t type)
{
	int i;

	for (i = 0; i < ARRAY_SIZE(hdat_i2c_devs); i++)
		if (hdat_i2c_devs[i].id == type)
			return &hdat_i2c_devs[i];

	return NULL;
}

static const char *map_label(uint32_t type)
{
	int i;

	for (i = 0; i < ARRAY_SIZE(hdat_i2c_labels); i++)
		if (hdat_i2c_labels[i].id == type)
			return hdat_i2c_labels[i].label;

	return NULL;
}

static bool is_zeros(const void *p, size_t size)
{
	const char *c = p;
	size_t i;

	for (i = 0; i < size; i++)
		if (c[i] != 0)
			return false;

	return true;
}

struct host_i2c_hdr {
	const struct HDIF_array_hdr hdr;
	__be32 version;
} __packed __align(0x4);

int parse_i2c_devs(const struct HDIF_common_hdr *hdr, int idata_index,
	struct dt_node *xscom)
{
	struct dt_node *i2cm, *bus, *node;
	const struct hdat_i2c_type *type;
	const struct i2c_dev *dev;
	const char *label, *name, *compat;
	const struct host_i2c_hdr *ahdr;
	uint32_t i2c_addr;
	uint32_t version;
	uint32_t size;
	uint32_t purpose;
	int i, count;

	/*
	 * This code makes a few assumptions about XSCOM addrs, etc
	 * and will need updating for new processors
	 */
	assert(proc_gen == proc_gen_p9);

	/*
	 * Emit an error if we get a newer version. This is an interim measure
	 * until the new version format is finalised.
	 */
	ahdr = HDIF_get_idata(hdr, idata_index, &size);
	if (!ahdr || !size)
		return -1;

	/*
	 * Some hostboots don't correctly fill the version field. On these
	 * the offset from the start of the header to the start of the array
	 * is 16 bytes.
	 */
	if (be32_to_cpu(ahdr->hdr.offset) == 16) {
		version = 1;
		prerror("I2C: HDAT device array has no version! Assuming v1\n");
	} else {
		version = be32_to_cpu(ahdr->version);
	}

	if (version == 2) {
		prerror("I2C: v%d found, but not supported. Parsing as v1\n",
			version);
	} else if (version > 2) {
		prerror("I2C: v%d found, but not supported! THIS IS A BUG\n",
			version);
		return -1;
	}

	count = HDIF_get_iarray_size(hdr, idata_index);
	for (i = 0; i < count; i++) {
		dev = HDIF_get_iarray_item(hdr, idata_index, i, &size);

		/*
		 * XXX: Some broken hostboots populate i2c devs with zeros.
		 * Workaround them for now.
		 */
		if (is_zeros(dev, size)) {
			prerror("I2C: Ignoring broken i2c dev %d\n", i);
			continue;
		}

		i2cm = get_i2cm_node(xscom, dev->i2cm_engine);
		bus = get_bus_node(i2cm, dev->i2cm_port,
			be16_to_cpu(dev->i2c_bus_freq));

		/*
		 * Looks like hostboot gives the address as an 8 bit, left
		 * justified quantity (i.e it includes the R/W bit). So we need
		 * to strip it off to get an address linux can use.
		 */
		i2c_addr = dev->i2c_addr >> 1;

		purpose = be32_to_cpu(dev->purpose);
		type = map_type(dev->type);
		label = map_label(purpose);

		/* HACK: Hostboot doesn't export the correct type information
		 * for the DIMM SPD EEPROMs. This is a problem because SPD
		 * EEPROMs have a different wire protocol to the atmel,24XXXX
		 * series. The main difference being that SPD EEPROMs have an
		 * 8bit offset rather than a 16bit offset. This means that the
		 * driver will send 2 bytes when doing a random read,
		 * potentially overwriting part of the SPD information.
		 *
		 * To work around this we force the compat string to "spd"
		 */
		if (proc_gen == proc_gen_p9 && dev->type == 0x2 &&
		    dev->i2cm_engine == 3) {
			compat = "spd";
			name = "eeprom";
		} else if (type) {
			compat = type->compat;
			name = type->name;
		} else {
			name = "unknown";
			compat = NULL;
		}

		/*
		 * An i2c device is unknown if either the i2c device list is
		 * outdated or the device is marked as unknown (0xFF) in the
		 * hdat. Log both cases to see what/where/why.
		 */
		if (!type || dev->type == 0xFF)
			prlog(PR_WARNING, "HDAT I2C: found e%dp%d - %s@%x (%#x:%s)\n",
			      dev->i2cm_engine, dev->i2cm_port, name, i2c_addr,
			      purpose, label);
		else
			prlog(PR_TRACE, "HDAT I2C: found e%dp%d - %s@%x (%#x:%s)\n",
			      dev->i2cm_engine, dev->i2cm_port, name, i2c_addr,
			      purpose, label);

		node = dt_new_addr(bus, name, i2c_addr);
		if (!node)
			continue;

		dt_add_property_cells(node, "reg", i2c_addr);
		dt_add_property_cells(node, "link-id",
			be32_to_cpu(dev->i2c_link));
		if (compat)
			dt_add_property_string(node, "compatible", compat);
		if (label)
			dt_add_property_string(node, "label", label);

		/* XXX: SLCA index? */
	}

	return 0;
}
