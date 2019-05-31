.. _OPAL_SENSOR_GROUP_CLEAR:

OPAL_SENSOR_GROUP_CLEAR
=======================

.. code-block:: c

   int opal_sensor_group_clear(u32 group_hndl, int token);

   #define OPAL_SENSOR_GROUP_CLEAR			156

OPAL call to clear the sensor groups data using a handle to identify
the type of sensor group which is exported via DT.

The call can be asynchronus, where the token parameter is used to wait
for the completion.


Returns
-------

:ref:`OPAL_SUCCESS`
  Success
:ref:`OPAL_UNSUPPORTED`
  No support for clearing the sensor group
:ref:`OPAL_HARDWARE`
  Unable to procced due to the current hardware state
:ref:`OPAL_PERMISSION`
  Hardware cannot take the request
:ref:`OPAL_ASYNC_COMPLETION`
  Request was sent and an async completion message will be sent with
  token and status of the request.
:ref:`OPAL_BUSY`
  Previous request in progress
:ref:`OPAL_INTERNAL_ERROR`
  Error in request response
:ref:`OPAL_TIMEOUT`
  Timeout in request completion
