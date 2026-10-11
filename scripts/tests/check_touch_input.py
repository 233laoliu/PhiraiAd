#!/usr/bin/env python3
"""Run CPU input regressions from the actual judge source without graphics.

Use --rustc/--sysroot if needed. This is an extracted-source check, not a full
application build: Vec2/Point math and Macroquad touch types are small stubs.
The production trackers/helpers and test bodies are copied unchanged.
"""
import argparse
from pathlib import Path
import re
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[2]
STUBS = '''#![allow(dead_code)]
use std::collections::{HashMap, HashSet};
#[derive(Clone,Copy,Debug,Default,PartialEq)] struct Vec2 { x:f32, y:f32 }
impl Vec2 {
 fn new(x:f32,y:f32)->Self{Self{x,y}}
 fn zeros()->Self{Self::new(0.,0.)}
 fn magnitude(self)->f32{self.x.hypot(self.y)}
 fn normalize(self)->Self{let n=self.magnitude();Self::new(self.x/n,self.y/n)}
 fn dot(self,v:&Self)->f32{self.x*v.x+self.y*v.y}
}
impl std::ops::Sub for Vec2 { type Output=Self;fn sub(self,r:Self)->Self{Self::new(self.x-r.x,self.y-r.y)} }
type Point=Vec2;type Vector=Vec2;
fn vec2(x:f32,y:f32)->Vec2{Vec2::new(x,y)}
#[derive(Clone,Copy,Debug,PartialEq)] enum TouchPhase { Started,Moved,Stationary,Ended,Cancelled }
#[derive(Clone,Debug)] struct Touch { id:u64, phase:TouchPhase, position:Vec2, time:f64 }
'''
EXISTING = {
 'flick_motion_is_converted_to_phigros_units',
 'missing_snapshot_clears_unconsumed_flick_on_stationary_frame',
 'missing_snapshot_rearms_consumed_flick_before_next_swipe',
 'snapshot_completion_preserves_fresh_input_and_excludes_terminal_fingers',
 'official_flick_uses_documented_threshold_and_consumption',
 'custom_flick_speed_threshold_controls_trigger_and_continuous_mode_survives_consume',
 'low_dpi_small_displacement_retriggers_after_previous_fast_projection',
 'official_flick_uses_frame_delta_even_if_clock_jumps',
 'official_flick_velocity_uses_one_sample_per_frame',
 'official_events_use_the_frame_clock_but_phira_keeps_raw_time',
 'active_finger_persists_until_terminal_event',
 'finger_order_is_stable_and_empty_snapshot_is_non_destructive',
 'orphan_move_rebind_starts_from_zero_velocity',
}


def function(source, name):
    start = source.index('    fn ' + name + '(')
    opening = source.index('{', start)
    depth = 1
    end = opening + 1
    while depth:
        depth += (source[end] == '{') - (source[end] == '}')
        end += 1
    return source[start:end]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--rustc', default='rustc')
    parser.add_argument('--sysroot')
    args = parser.parse_args()
    source = (ROOT / 'prpr/src/judge.rs').read_text()
    test_start = source.index('    fn input_sample(')
    test_end = source.index('    #[test]\n    fn flick_motion_is_converted_to_phigros_units()', test_start)
    new_tests = source[test_start:test_end]
    helpers_start = source.index('pub struct FlickTracker')
    helpers_end = source.index('/// Stable, serializable copy', helpers_start)
    constants = '\n'.join(re.findall(r'^(?:pub )?const (?:FLICK_SPEED_THRESHOLD|PHIGROS_X_UNIT):[^\n]*', source, re.M))
    replica_path = (ROOT / 'prpr/src/phigros_judge.rs').as_posix()
    program = STUBS + constants + '\n#[path="' + replica_path + '"] mod replica;\n'
    program += source[helpers_start:helpers_end]
    noise = (ROOT / 'prpr/src/noise_area.rs').read_text()
    state_start = noise.index('#[derive(Clone, Copy, Debug, Default)]\npub struct Hover')
    state_end = noise.index('#[cfg(test)]\nmod tests', state_start)
    # Geometry is unchanged. The stub always reports no region, so these tests
    # exercise actual latching/release/hover code with contact state set by tests.
    program += '\nstruct BlockArea;\nfn blocked(_: &[BlockArea], _: Vec2, _: f32, _: f32) -> bool { false }\n'
    program += noise[state_start:state_end]
    program += '\n#[cfg(test)] mod tests { use super::*;\n' + new_tests
    program += '\n'.join('#[test]\n' + function(source, name) for name in sorted(EXISTING)) + '\n}\n'
    with tempfile.TemporaryDirectory(prefix='phiraiad-touch-tests-') as directory:
        script, binary = Path(directory) / 'input.rs', Path(directory) / 'input-tests'
        script.write_text(program)
        command = [args.rustc, '--edition=2021', '--test', str(script), '-o', str(binary)]
        if args.sysroot:
            command += ['--sysroot', args.sysroot]
        subprocess.run(command, check=True)
        subprocess.run([str(binary)], check=True)


if __name__ == '__main__':
    main()
