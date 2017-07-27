ibm,opal/sensor-groups
----------------------

This node contains all sensor groups defined in the system.
Each child node here represents a sensor group.

For example : ::
        occ-csm@1c00020/

The compatible property is set to "ibm,opal-occ-sensor-group"

Each child node has below properties:

`type`
  string to indicate the sensor group

`sensor-group-id`
  Uniquely identifies a sensor group.

`ibm,chip-id`
  This property is added if the sensor group is chip specific

`sensors`
  Phandles of all sensors belonging to this sensor group

.. code-block:: dts

   ibm,opal {
     sensor-groups {
        compatible = "ibm,opal-occ-sensor-group";

        occ-csm@1c00020 {
                name = "occ-csm"
                type = "csm"
                sensor-group-id = <0x01c00020>
                ibm,chip-id = <0x00000008>
                phandles = <
        };
     };
    };
