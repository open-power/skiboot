OPAL_SENSOR_READ_U64
====================

The OPAL sensor call to read sensor data of type u64. Unlike
opal_sensor_read which reads upto u32 this call can be used to
read values of sensors upto 64bits. The calling conventions and
return values are same as OPAL_SENSOR_READ.
(ref: doc/opal-api/opal-sensor-read-88.rst)

Parameters
----------
::

	u32 sensor_handler
	int	 token
	u64 *sensor_data
