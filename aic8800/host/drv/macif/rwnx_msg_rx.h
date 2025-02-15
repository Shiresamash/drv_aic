/**
 ****************************************************************************************
 *
 * @file rwnx_msg_rx.h
 *
 * @brief RX function declarations
 *
 * Copyright (C) RivieraWaves 2012-2019
 *
 ****************************************************************************************
 */

#ifndef _RWNX_MSG_RX_H_
#define _RWNX_MSG_RX_H_

void rwnx_rx_handle_msg(struct rwnx_hw *rwnx_hw, struct e2a_msg *msg);

int rwnx_force_scan_stop(void);

#endif /* _RWNX_MSG_RX_H_ */
