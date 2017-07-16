/* Modules for enabling and disabling tso feature */

#include <stdbool.h>

/* Detemine whether the status of tso is changable, false for "fixed" */
static bool IsChangable(char *deviceName)
{
    
    

}

/* Enable tso feature in given NIC, return ture if successfully enabled */
static bool EnableTSO(char *deviceName)
{
    /* If it is fixed, return false */
    if (!IsChangable(deviceName))
    {
        return false;
    }

    /* Try to enable it */
}

/* Disable tso feature in given NIC, return true if successfully diabled */
static bool DisableTSO(char *deviceName)
{
    /* If it is fixed, return false */
    if (!IsChangable(deviceName))
    {
        return false;
    }

    /* Try to disable it */
}
