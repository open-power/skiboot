OPAL_CHECK_ASYNC_COMPLETION
===========================

OPAL_CHECK_ASYNC_COMPLETION checks if an async OPAL pending message was completed. (see :ref:`opal-messages`).

.. code-block:: c

   int64_t opal_check_completion(uint64_t *buffer, uint64_t size, uint64_t token);

Parameters:

buffer
  buffer to copy message into
size
  sizeof buffer to copy message into
token
  async message token


Return values
-------------

OPAL_PARAMETER
  buffer parameter is an invalid pointer (NULL or > top of RAM).

OPAL_SUCCESS
  message successfully copied to buffer.

OPAL_BUSY
  message is still pending and should be re-checked later.
