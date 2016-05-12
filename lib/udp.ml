(*
 * Copyright (c) 2010-2014 Anil Madhavapeddy <anil@recoil.org>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 *)

open Lwt.Infix

module Make(Ip: V1_LWT.IP) = struct

  type 'a io    = 'a Lwt.t
  type buffer   = Cstruct.t
  type ip       = Ip.t
  type ipaddr   = Ip.ipaddr
  type ipinput  = src:ipaddr -> dst:ipaddr -> buffer -> unit io
  type callback = src:ipaddr -> dst:ipaddr -> src_port:int -> Cstruct.t -> unit Lwt.t

  (** IO operation errors *)
  type error = [
    | `Unknown of string (** an undiagnosed error *)
  ]

  type t = {
    ip : Ip.t;
  }

  let id {ip} = ip

  let respond_u1 ~src ~dst ~src_port t ip_hdr buf =
    let frame, hdr_len = Ip.allocate_frame t.ip ~dst:src ~proto:`ICMP in
    let frame = Cstruct.set_len frame
      (hdr_len + Wire_structs.Ipv4_wire.sizeof_icmpv4)
    in
    let icmp_frame = Cstruct.shift frame hdr_len in
    Wire_structs.Ipv4_wire.set_icmpv4_csum icmp_frame 0;
    Wire_structs.Ipv4_wire.set_icmpv4_ty icmp_frame 3;
    Wire_structs.Ipv4_wire.set_icmpv4_code icmp_frame 3;
    match buf with
    | data :: tl when Cstruct.len data == 300 ->
      let extra_data = Cstruct.sub data 0 20 in (*Without extra, comes to 0x164, want 178 *)
      Ip.writev t.ip frame (ip_hdr::extra_data::[data])
    | _ ->
      Ip.writev t.ip frame [ip_hdr]

  let input ~listeners _t ~src ~dst buf =
    let ihl = (Wire_structs.Ipv4_wire.get_ipv4_hlen_version buf land 0xf) * 4 in
    let payload_len = Wire_structs.Ipv4_wire.get_ipv4_len buf - ihl in
    (* Headers are 48 bytes total - 48 + 128 = 176 = 0xb0 *)
    let icmp_split_point =
      if Cstruct.len buf > (ihl + 128) then
        (ihl + Wire_structs.sizeof_udp) (* Use data *)
      else
        (ihl + 8)
    in
    let icmp_data, _ = Cstruct.split buf icmp_split_point in
    let ip_hdr, udp_pkt = Cstruct.split buf ihl in
    let udp_pkt =
      if Cstruct.len udp_pkt > payload_len then
        Cstruct.sub udp_pkt 0 payload_len
      else
        udp_pkt
    in
    let dst_port = Wire_structs.get_udp_dest_port udp_pkt in
    let data =
      Cstruct.sub udp_pkt Wire_structs.sizeof_udp
        (Wire_structs.get_udp_length udp_pkt - Wire_structs.sizeof_udp)
    in
    if Cstruct.len data == 300 then
      Printf.printf "\n300 bytes of data in UDP packet\n";
    let src_port = Wire_structs.get_udp_source_port udp_pkt in
    match listeners ~dst_port with
(* HERE nmap's U1 probe is sent to a closed port, so should be handled here   *)
    | None    ->
      respond_u1 ~src ~dst ~src_port _t icmp_data [data]
    | Some fn ->
      fn ~src ~dst ~src_port data

  let writev ?source_port ~dest_ip ~dest_port t bufs =
    begin match source_port with
      | None   -> Lwt.fail (Failure "TODO; random source port")
      | Some p -> Lwt.return p
    end >>= fun source_port ->
    let frame, header_len = Ip.allocate_frame t.ip ~dst:dest_ip ~proto:`UDP in
    let frame = Cstruct.set_len frame (header_len + Wire_structs.sizeof_udp) in
    let udp_buf = Cstruct.shift frame header_len in
    Wire_structs.set_udp_source_port udp_buf source_port;
    Wire_structs.set_udp_dest_port udp_buf dest_port;
    Wire_structs.set_udp_length udp_buf (Wire_structs.sizeof_udp + Cstruct.lenv bufs);
    (* Wire_structs.set_udp_checksum udp_buf 0; *)
    let csum = Ip.checksum frame (udp_buf :: bufs) in
    Wire_structs.set_udp_checksum udp_buf csum;
    Ip.writev t.ip frame bufs

  let write ?source_port ~dest_ip ~dest_port t buf =
    writev ?source_port ~dest_ip ~dest_port t [buf]

  let connect ip = Lwt.return (`Ok { ip })

  let disconnect _ = Lwt.return_unit
end
