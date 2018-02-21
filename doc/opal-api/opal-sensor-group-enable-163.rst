.. _opal-sensor-groups-enable:

OPAL_SENSOR_GROUP_ENABLE
==========================
OPAL call to enable/disable the sensor group using a handle to identify
the type of sensor group provided in the device tree.

For example this call is used to disable/enable copying of sensor
group by OCC to main memory.

The call can be asynchronus, where the token parameter is used to wait
for the completion.

Parameters
----------
::
        u32 handle
        int token
        bool enable

Returns
-------
OPAL_SUCCESS
  Success

OPAL_UNSUPPORTED
  No support to enable/disable the sensor group

OPAL_HARDWARE
  Unable to procced due to the current hardware state

OPAL_PERMISSION
  Hardware cannot take the request

OPAL_ASYNC_COMPLETION
  Request was sent and an async completion message will be sent with
  token and status of the request.

OPAL_BUSY
  Previous request in progress

OPAL_INTERNAL_ERROR
  Error in request response

OPAL_TIMEOUT
  Timeout in request completion
